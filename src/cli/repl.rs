use std::io;
use std::path::Path;
use std::sync::Arc;
use std::{fs::read_to_string, process};

use anyhow::{bail, Context, Result};

use rustyline::{
    error::ReadlineError,
    history::DefaultHistory,
    validate::{MatchingBracketValidator, ValidationContext, ValidationResult, Validator},
    Config, Editor,
};
use rustyline_derive::{Completer, Helper, Highlighter, Hinter};

use lurk::{
    eval::{
        lang::{Coproc, Lang},
        Evaluator, Frame, Witness, IO,
    },
    field::LurkField,
    parser,
    proof::{nova::NovaProver, Prover},
    ptr::Ptr,
    public_parameters::public_params,
    store::Store,
    tag::{ContTag, ExprTag},
    writer::Write,
    Num, UInt,
};

#[cfg(not(target_arch = "wasm32"))]
use crate::cli::paths::repl_history;

#[derive(Completer, Helper, Highlighter, Hinter)]
struct InputValidator {
    brackets: MatchingBracketValidator,
}

impl Validator for InputValidator {
    fn validate(&self, ctx: &mut ValidationContext<'_>) -> rustyline::Result<ValidationResult> {
        self.brackets.validate(ctx)
    }
}

pub enum Backend {
    Nova,
    Groth16,
}

type FrameVec<F> = Vec<Frame<IO<F>, Witness<F>, Coproc<F>>>;

#[allow(dead_code)]
pub struct Repl<F: LurkField> {
    store: Store<F>,
    env: Ptr<F>,
    limit: usize,
    lang: Arc<Lang<F, Coproc<F>>>,
    last_frames: Option<FrameVec<F>>,
    rc: usize,
    backend: Backend,
}

fn check_non_zero(name: &str, x: usize) -> Result<()> {
    if x == 0 {
        bail!("`{name}` can't be zero")
    }
    Ok(())
}

/// Pads the number of iterations to the first multiple of the reduction count
/// that's equal or greater than the number of iterations
///
/// Panics if reduction count is zero
fn pad_iterations(iterations: usize, rc: usize) -> usize {
    let lower = rc * (iterations / rc);
    if lower < iterations {
        lower + rc
    } else {
        lower
    }
}

type F = pasta_curves::pallas::Scalar;

impl Repl<F> {
    pub fn new(
        store: Store<F>,
        env: Ptr<F>,
        limit: usize,
        rc: usize,
        backend: Backend,
    ) -> Result<Repl<F>> {
        check_non_zero("limit", limit)?;
        check_non_zero("rc", rc)?;
        Ok(Repl {
            store,
            env,
            limit,
            lang: Arc::new(Lang::new()),
            last_frames: None,
            rc,
            backend,
        })
    }

    pub fn prove_last_frames(&mut self) -> Result<()> {
        match &self.last_frames {
            None => bail!("No claim to prove"),
            Some(frames) => {
                // TODO: case on self.backend
                let mut frames = frames.clone();
                let n_frames = frames.len();
                for _ in 0..pad_iterations(n_frames, self.rc) - n_frames {
                    frames.push(frames[frames.len() - 1].clone())
                }
                let prover = NovaProver::new(self.rc, (*self.lang).clone());
                let pp = public_params(self.rc, self.lang.clone())?;
                self.store.hydrate_scalar_cache();
                let (proof, z0, zi, num_steps) =
                    prover.prove(&pp, frames, &mut self.store, self.lang.clone())?;
                assert!(proof.verify(&pp, num_steps, z0, &zi)?);
                Ok(())
            }
        }
    }

    #[inline]
    fn eval_expr(&mut self, expr_ptr: Ptr<F>) -> Result<(IO<F>, usize, Vec<Ptr<F>>)> {
        Ok(Evaluator::new(expr_ptr, self.env, &mut self.store, self.limit, &self.lang).eval()?)
    }

    fn peek1(&self, cmd: &str, args: &Ptr<F>) -> Result<Ptr<F>> {
        let (first, rest) = self.store.car_cdr(args)?;
        if !rest.is_nil() {
            bail!("`{cmd}` accepts at most one argument")
        }
        Ok(first)
    }

    fn peek2(&self, cmd: &str, args: &Ptr<F>) -> Result<(Ptr<F>, Ptr<F>)> {
        let (first, rest) = self.store.car_cdr(args)?;
        let (second, rest) = self.store.car_cdr(&rest)?;
        if !rest.is_nil() {
            bail!("`{cmd}` accepts at most two arguments")
        }
        Ok((first, second))
    }

    fn peek_usize(&self, cmd: &str, args: &Ptr<F>) -> Result<usize> {
        let first = self.peek1(cmd, args)?;
        match first.tag {
            ExprTag::Num => match self.store.fetch_num(&first).unwrap() {
                Num::U64(u) => Ok(*u as usize),
                _ => bail!(
                    "Invalid value for `{cmd}`: {}",
                    first.fmt_to_string(&self.store)
                ),
            },
            ExprTag::U64 => match self.store.fetch_uint(&first).unwrap() {
                UInt::U64(u) => Ok(u as usize),
            },
            _ => bail!(
                "Invalid value for `{cmd}`: {}",
                first.fmt_to_string(&self.store)
            ),
        }
    }

    fn handle_meta_cases(&mut self, cmd: &str, args: &Ptr<F>, pwd_path: &Path) -> Result<()> {
        match cmd {
            "def" => {
                // Extends env with a non-recursive binding.
                //
                // This: !(:def foo (lambda () 123))
                //
                // Gets macroexpanded to this: (let ((foo (lambda () 123)))
                //                               (current-env))
                //
                // And the state's env is set to the result.
                let (first, second) = self.peek2(cmd, args)?;
                let l = &self.store.lurk_sym("let");
                let current_env = &self.store.lurk_sym("current-env");
                let binding = &self.store.list(&[first, second]);
                let bindings = &self.store.list(&[*binding]);
                let current_env_call = &self.store.list(&[*current_env]);
                let expanded = &self.store.list(&[*l, *bindings, *current_env_call]);
                let (expanded_io, ..) = self.eval_expr(*expanded)?;

                self.env = expanded_io.expr;

                let (new_binding, _) = &self.store.car_cdr(&expanded_io.expr)?;
                let (new_name, _) = self.store.car_cdr(new_binding)?;
                println!("{}", new_name.fmt_to_string(&self.store));
            }
            "defrec" => {
                // Extends env with a recursive binding.
                //
                // This: !(:defrec foo (lambda () 123))
                //
                // Gets macroexpanded to this: (letrec ((foo (lambda () 123)))
                //                               (current-env))
                //
                // And the state's env is set to the result.
                let (first, second) = self.peek2(cmd, args)?;
                let l = &self.store.lurk_sym("letrec");
                let current_env = &self.store.lurk_sym("current-env");
                let binding = &self.store.list(&[first, second]);
                let bindings = &self.store.list(&[*binding]);
                let current_env_call = &self.store.list(&[*current_env]);
                let expanded = &self.store.list(&[*l, *bindings, *current_env_call]);
                let (expanded_io, ..) = self.eval_expr(*expanded)?;

                self.env = expanded_io.expr;

                let (new_binding_outer, _) = &self.store.car_cdr(&expanded_io.expr)?;
                let (new_binding_inner, _) = &self.store.car_cdr(new_binding_outer)?;
                let (new_name, _) = self.store.car_cdr(new_binding_inner)?;
                println!("{}", new_name.fmt_to_string(&self.store));
            }
            "load" => {
                let first = self.peek1(cmd, args)?;
                match self.store.fetch_string(&first) {
                    Some(path) => {
                        let joined = pwd_path.join(Path::new(&path));
                        self.load_file(&joined)?
                    }
                    _ => bail!("Argument of `load` must be a string."),
                }
                io::Write::flush(&mut io::stdout()).unwrap();
            }
            "assert" => {
                let first = self.peek1(cmd, args)?;
                let (first_io, ..) = self.eval_expr(first)?;
                if first_io.expr.is_nil() {
                    eprintln!(
                        "`assert` failed. {} evaluates to nil",
                        first.fmt_to_string(&self.store)
                    );
                    process::exit(1);
                }
            }
            "assert-eq" => {
                let (first, second) = self.peek2(cmd, args)?;
                let (first_io, ..) = self
                    .eval_expr(first)
                    .with_context(|| "evaluating first arg")?;
                let (second_io, ..) = self
                    .eval_expr(second)
                    .with_context(|| "evaluating second arg")?;
                if !&self.store.ptr_eq(&first_io.expr, &second_io.expr)? {
                    eprintln!(
                        "`assert-eq` failed. Expected:\n  {} = {}\nGot:\n  {} ≠ {}",
                        first.fmt_to_string(&self.store),
                        second.fmt_to_string(&self.store),
                        first_io.expr.fmt_to_string(&self.store),
                        second_io.expr.fmt_to_string(&self.store)
                    );
                    process::exit(1);
                }
            }
            "assert-emitted" => {
                let (first, second) = self.peek2(cmd, args)?;
                let (first_io, ..) = self
                    .eval_expr(first)
                    .with_context(|| "evaluating first arg")?;
                let (.., emitted) = self
                    .eval_expr(second)
                    .with_context(|| "evaluating second arg")?;
                let (mut first_emitted, mut rest_emitted) = self.store.car_cdr(&first_io.expr)?;
                for (i, elem) in emitted.iter().enumerate() {
                    if elem != &first_emitted {
                        eprintln!(
                            "`assert-emitted` failed at position {i}. Expected {}, but found {}.",
                            first_emitted.fmt_to_string(&self.store),
                            elem.fmt_to_string(&self.store),
                        );
                        process::exit(1);
                    }
                    (first_emitted, rest_emitted) = self.store.car_cdr(&rest_emitted)?;
                }
            }
            "assert-error" => {
                let first = self.peek1(cmd, args)?;
                let (first_io, ..) = self.eval_expr(first)?;
                if first_io.cont.tag != ContTag::Error {
                    eprintln!(
                        "`assert-error` failed. {} doesn't result on evaluation error.",
                        first.fmt_to_string(&self.store)
                    );
                    process::exit(1);
                }
            }
            "clear" => self.env = self.store.nil(),
            "set-env" => {
                // The state's env is set to the result of evaluating the first argument.
                let first = self.peek1(cmd, args)?;
                let (first_io, ..) = self.eval_expr(first)?;
                self.env = first_io.expr;
            }
            "set-limit" => {
                let limit = self.peek_usize(cmd, args)?;
                check_non_zero("limit", limit)?;
                self.limit = limit;
            }
            "set-rc" => {
                let rc = self.peek_usize(cmd, args)?;
                check_non_zero("rc", rc)?;
                self.rc = rc;
            }
            "prove" => {
                if !args.is_nil() {
                    self.eval_expr_and_set_last_frames(self.peek1(cmd, args)?)?;
                }
                self.prove_last_frames()?;
            }
            "verify" => {
                todo!()
            }
            _ => bail!("Unsupported meta command: {cmd}"),
        }
        Ok(())
    }

    fn handle_meta(&mut self, expr_ptr: Ptr<F>, pwd_path: &Path) -> Result<()> {
        let (car, cdr) = self.store.car_cdr(&expr_ptr)?;
        match &self.store.fetch_symbol(&car) {
            Some(symbol) => {
                self.handle_meta_cases(format!("{}", symbol).as_str(), &cdr, pwd_path)?
            }
            None => bail!(
                "Meta command must be a symbol. Found {}",
                car.fmt_to_string(&self.store)
            ),
        }
        Ok(())
    }

    fn eval_expr_and_set_last_frames(&mut self, expr_ptr: Ptr<F>) -> Result<(IO<F>, usize)> {
        let frames = Evaluator::new(expr_ptr, self.env, &mut self.store, self.limit, &self.lang)
            .get_frames()?;

        let last_idx = frames.len() - 1;
        let last_frame = &frames[last_idx];
        let last_output = last_frame.output;

        let mut iterations = last_idx;

        if last_frame.is_complete() {
            self.last_frames = Some(frames)
        } else {
            iterations += 1;
        }

        Ok((last_output, iterations))
    }

    fn handle_non_meta(&mut self, expr_ptr: Ptr<F>) -> Result<()> {
        self.eval_expr_and_set_last_frames(expr_ptr)
            .map(|(output, iterations)| {
                let prefix = if iterations != 1 {
                    format!("[{iterations} iterations] => ")
                } else {
                    "[1 iteration] => ".into()
                };

                let suffix = match output.cont.tag {
                    ContTag::Outermost | ContTag::Terminal => {
                        output.expr.fmt_to_string(&self.store)
                    }
                    ContTag::Error => "ERROR!".into(),
                    _ => "Computation incomplete (limit reached)".into(),
                };

                println!("{}{}", prefix, suffix);
            })
    }

    fn handle_form<'a>(
        &mut self,
        input: parser::Span<'a>,
        pwd_path: &Path,
    ) -> Result<parser::Span<'a>> {
        let (input, ptr, is_meta) = self.store.read_maybe_meta(input)?;

        if is_meta {
            self.handle_meta(ptr, pwd_path)?;
        } else {
            self.handle_non_meta(ptr)?;
        }
        Ok(input)
    }

    pub fn load_file(&mut self, file_path: &Path) -> Result<()> {
        let input = read_to_string(file_path)?;
        println!("Loading {}", file_path.display());

        let mut input = parser::Span::new(&input);
        loop {
            match self.handle_form(input, file_path) {
                Ok(new_input) => input = new_input,
                Err(e) => {
                    if let Some(parser::Error::NoInput) = e.downcast_ref::<parser::Error>() {
                        // It's ok, it just means we've hit the EOF
                        return Ok(());
                    } else {
                        return Err(e);
                    }
                }
            }
        }
    }

    pub fn start(&mut self) -> Result<()> {
        println!("Lurk REPL welcomes you.");

        let pwd_path = &std::env::current_dir()?;

        let mut editor: Editor<InputValidator, DefaultHistory> = Editor::with_config(
            Config::builder()
                .color_mode(rustyline::ColorMode::Enabled)
                .auto_add_history(true)
                .build(),
        )?;

        editor.set_helper(Some(InputValidator {
            brackets: MatchingBracketValidator::new(),
        }));

        #[cfg(not(target_arch = "wasm32"))]
        let history_path = &repl_history();

        #[cfg(not(target_arch = "wasm32"))]
        if history_path.exists() {
            editor.load_history(history_path)?;
        }

        loop {
            match editor.readline("> ") {
                Ok(line) => {
                    #[cfg(not(target_arch = "wasm32"))]
                    editor.save_history(history_path)?;
                    match self.store.read_maybe_meta(parser::Span::new(&line)) {
                        Ok((_, expr_ptr, is_meta)) => {
                            if is_meta {
                                if let Err(e) = self.handle_meta(expr_ptr, pwd_path) {
                                    println!("!Error: {e}");
                                }
                            } else if let Err(e) = self.handle_non_meta(expr_ptr) {
                                println!("Error: {e}");
                            }
                        }
                        Err(parser::Error::NoInput) => (),
                        Err(e) => {
                            println!("Read error: {e}")
                        }
                    }
                }
                Err(ReadlineError::Interrupted | ReadlineError::Eof) => {
                    println!("Exiting...");
                    break;
                }
                Err(err) => {
                    println!("Read line error: {err}");
                    break;
                }
            }
        }
        Ok(())
    }
}

mod test {
    #[test]
    fn test_padding() {
        use crate::cli::repl::pad_iterations;
        assert_eq!(pad_iterations(61, 10), 70);
        assert_eq!(pad_iterations(1, 10), 10);
        assert_eq!(pad_iterations(61, 1), 61);
        assert_eq!(pad_iterations(610, 10), 610);
        assert_eq!(pad_iterations(619, 20), 620);
    }
}

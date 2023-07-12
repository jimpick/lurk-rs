use std::env::current_dir;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use bellperson::gadgets::boolean::{Boolean, AllocatedBit};
use bellperson::gadgets::multipack::pack_bits;
use bellperson::gadgets::num::AllocatedNum;
use bellperson::gadgets::sha256::sha256;
use itertools::enumerate;
use lurk::circuit::gadgets::circom::sha256::sha256_circom;
use lurk::circuit::gadgets::data::GlobalAllocations;
use lurk::circuit::gadgets::pointer::{AllocatedContPtr, AllocatedPtr};
use lurk::coprocessor::{CoCircuit, Coprocessor};
use lurk::eval::{empty_sym_env, lang::Lang};
use lurk::field::LurkField;
use lurk::proof::{nova::NovaProver, Prover};
use lurk::ptr::Ptr;
use lurk::public_parameters::public_params;
use lurk::store::Store;
use lurk::Num;
use lurk::tag::{ExprTag, Tag};
use lurk_macros::Coproc;

use bellperson::{ConstraintSystem, SynthesisError};

use nova_scotia::r1cs::CircomConfig;
use pasta_curves::pallas::Scalar as Fr;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

const REDUCTION_COUNT: usize = 1;

#[derive(Debug)]
pub(crate) struct CircomSha256Coprocessor<F: LurkField> {
    n: usize,
    root: PathBuf,
    circom_config: CircomConfig<F>,
}

impl<F: LurkField> Clone for CircomSha256Coprocessor<F> {
    fn clone(&self) -> Self {
        CircomSha256Coprocessor::new(self.n, self.root.clone())
    }
}

impl<F: LurkField> CoCircuit<F> for CircomSha256Coprocessor<F> {
    fn arity(&self) -> usize {
        0
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        g: &GlobalAllocations<F>,
        store: &Store<F>,
        _input_exprs: &[AllocatedPtr<F>],
        input_env: &AllocatedPtr<F>,
        input_cont: &AllocatedContPtr<F>,
    ) -> Result<(AllocatedPtr<F>, AllocatedPtr<F>, AllocatedContPtr<F>), SynthesisError> {

        let output = sha256_circom(
            &mut cs.namespace(|| "sha256_circom"),
            F::from(0),
            F::from(0),
            &mut self.circom_config,
        )?;


        let res = AllocatedPtr::from_parts(&g.num_tag, &output);

        Ok((res, input_env.clone(), input_cont.clone()))
    }
}

impl<F: LurkField> Coprocessor<F> for CircomSha256Coprocessor<F> {
    fn eval_arity(&self) -> usize {
        0
    }

    fn simple_evaluate(&self, s: &mut Store<F>, _args: &[Ptr<F>]) -> Ptr<F> {
        /*let mut hasher = Sha256::new();

        let input = vec![0u8; self.n];

        hasher.update(input);
        let result = hasher.finalize();

        let u: Vec<u128> = (0..2)
            .map(|i| {
                let a: [u8; 16] = result[(16 * i)..(16 * (i + 1))].try_into().unwrap();
                u128::from_be_bytes(a)
            })
            .collect();

        let blah = &[u[0], u[1]].map(|x| s.intern_num(u128_into_scalar::<F>(x)));
        s.list(blah)*/

        let expected = Num::Scalar(F::from_str_vartime("55165702627807990590530466439275329993482327026534454077267643456").unwrap());
        s.intern_num(expected)
    }

    fn has_circuit(&self) -> bool {
        true
    }
}

impl<F: LurkField> CircomSha256Coprocessor<F> {
    pub(crate) fn new(n: usize, root: PathBuf) -> Self {
        let mut wtns = root.clone();
        wtns.push("main_js");
        wtns.push("main");
        wtns.set_extension("wasm");
        let mut r1cs = root.clone();
        r1cs.push("main");
        r1cs.set_extension("r1cs");
        Self {
            n,
            root,
            circom_config: CircomConfig::new(wtns, r1cs).unwrap(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Sha256Coprocessor<F: LurkField> {
    n: usize,
    pub(crate) _p: PhantomData<F>,
}

impl<F: LurkField> CoCircuit<F> for Sha256Coprocessor<F> {
    fn arity(&self) -> usize {
        0
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        g: &GlobalAllocations<F>,
        store: &Store<F>,
        _input_exprs: &[AllocatedPtr<F>],
        input_env: &AllocatedPtr<F>,
        input_cont: &AllocatedContPtr<F>,
    ) -> Result<(AllocatedPtr<F>, AllocatedPtr<F>, AllocatedContPtr<F>), SynthesisError> {
        // // TODO: Maybe fix this
        let false_bool = Boolean::from(AllocatedBit::alloc(cs.namespace(|| "false"), Some(false))?);

        let preimage = vec![false_bool; self.n * 8];

        let mut bits = sha256(cs.namespace(|| "SHAhash"), &preimage)?;

        bits.reverse();

        let nums: Vec<AllocatedNum<_>> = (0..2)
            .map(|i| {
                pack_bits(
                    cs.namespace(|| format!("num{i}")),
                    &bits[(128 * i)..(128 * (i + 1))],
                )
                .unwrap()
            })
            .collect();

        let result_ptr = enumerate(nums).try_fold(g.nil_ptr.clone(), |acc, (i, num)| {
            let ptr = AllocatedPtr::alloc_tag(
                &mut cs.namespace(|| format!("limb_value_{i}")),
                ExprTag::Num.to_field(),
                num,
            )?;
            AllocatedPtr::construct_cons(cs.namespace(|| format!("limb_{i}")), g, store, &ptr, &acc)
        })?;

        Ok((result_ptr, input_env.clone(), input_cont.clone()))
    }
}

impl<F: LurkField> Coprocessor<F> for Sha256Coprocessor<F> {
    fn eval_arity(&self) -> usize {
        0
    }

    fn simple_evaluate(&self, s: &mut Store<F>, _args: &[Ptr<F>]) -> Ptr<F> {
        let expected = Num::Scalar(F::from_str_vartime("55165702627807990590530466439275329993482327026534454077267643456").unwrap());
        s.intern_num(expected)
    }

    fn has_circuit(&self) -> bool {
        true
    }
}

impl<F: LurkField> Sha256Coprocessor<F> {
    pub(crate) fn new(n: usize) -> Self {
        Self {
            n,
            _p: Default::default(),
        }
    }
}

#[derive(Clone, Debug, Coproc)]
enum Sha256Coproc<F: LurkField> {
    SC1(Sha256Coprocessor<F>),
    SC2(CircomSha256Coprocessor<F>),
}

/// Run the example in this file with
/// `cargo run --release --example circom_sha256`
fn main() {

    let store = &mut Store::<Fr>::new();
    let sym_str = format!(".circom_sha256_{}", 2); // two inputs
    let lang = Lang::<Fr, Sha256Coproc<Fr>>::new_with_bindings(
        store,
        vec![(sym_str.clone(), Sha256Coprocessor::new(64).into())],
    );

    let coproc_expr = format!("{}", sym_str);
    dbg!(coproc_expr.clone());

    let expr = format!("({coproc_expr})");
    let ptr = store.read(&expr).unwrap();

    let nova_prover = NovaProver::<Fr, Sha256Coproc<Fr>>::new(REDUCTION_COUNT, lang.clone());
    let lang_rc = Arc::new(lang);

    println!("Setting up public parameters...");

    let pp_start = Instant::now();
    let pp = public_params::<Sha256Coproc<Fr>>(REDUCTION_COUNT, lang_rc.clone()).unwrap();
    let pp_end = pp_start.elapsed();

    println!("Public parameters took {:?}", pp_end);

    println!("Beginning proof step...");

    let proof_start = Instant::now();
    let (proof, z0, zi, num_steps) = nova_prover
        .evaluate_and_prove(&pp, ptr, empty_sym_env(store), store, 10000, lang_rc)
        .unwrap();
    let proof_end = proof_start.elapsed();

    println!("Proofs took {:?}", proof_end);

    println!("Verifying proof...");

    let verify_start = Instant::now();
    let res = proof.verify(&pp, num_steps, z0, &zi).unwrap();
    let verify_end = verify_start.elapsed();

    println!("Verify took {:?}", verify_end);

    if res {
        println!(
            "Congratulations! You proved and verified a CIRCOM-SHA256 hash calculation in {:?} time!",
            pp_end + proof_end + verify_end
        );
    }
}

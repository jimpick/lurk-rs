mod cli;

use anyhow::Result;

fn main() -> Result<()> {
    pretty_env_logger::init();
    println!(
        "commit: {} {}",
        env!("VERGEN_GIT_COMMIT_DATE"),
        env!("VERGEN_GIT_SHA")
    );
    cli::parse_and_run()
}

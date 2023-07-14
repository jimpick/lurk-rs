use serde::{Deserialize, Serialize};

#[cfg(not(target_arch = "wasm32"))]
use anyhow::Result;

use lurk::{
    eval::{
        lang::{Coproc, Lang},
        Status,
    },
    field::LanguageField,
    proof::nova,
};

#[cfg(not(target_arch = "wasm32"))]
use lurk::{proof::nova::PublicParams, public_parameters::public_params};

#[cfg(not(target_arch = "wasm32"))]
use super::paths::proof_path;

type F = pasta_curves::pallas::Scalar;

#[derive(Serialize, Deserialize)]
pub struct ProofInfo {
    pub field: LanguageField,
    pub rc: usize,
    pub lang: Lang<F, Coproc<F>>,
    pub iterations: usize,
    pub generation_cost: u128,
    pub compression_cost: u128,
    pub status: Status,
    pub expression: Option<String>,
    pub environment: Option<String>,
    pub result: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct NovaProof<'a> {
    pub proof: nova::Proof<'a, Coproc<F>>,
    pub public_inputs: Vec<F>,
    pub public_outputs: Vec<F>,
    pub num_steps: usize,
}

impl<'a> NovaProof<'a> {
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn verify(&self, pp: &PublicParams<'_, Coproc<F>>) -> Result<bool> {
        let Self {
            proof,
            public_inputs,
            public_outputs,
            num_steps,
        } = self;
        Ok(proof.verify(pp, *num_steps, public_inputs, public_outputs)?)
    }
}

#[derive(Serialize, Deserialize)]
pub enum LurkProof<'a> {
    Nova {
        nova_proof: NovaProof<'a>,
        proof_info: ProofInfo,
    },
}

impl<'a> LurkProof<'a> {
    #[cfg(not(target_arch = "wasm32"))]
    pub fn verify_proof(proof_id: &str) -> Result<()> {
        use crate::cli::repl::Backend;
        use log::info;
        use std::{fs::File, io::BufReader, sync::Arc};

        let file = File::open(proof_path(proof_id))?;
        let reader = BufReader::new(file);
        let lurk_proof: LurkProof = bincode::deserialize_from(reader)?;
        match lurk_proof {
            LurkProof::Nova {
                nova_proof,
                proof_info,
            } => {
                Backend::Nova.validate_field(&proof_info.field)?;

                info!("Loading public parameters");
                let pp = public_params(proof_info.rc, Arc::new(proof_info.lang))?;

                if nova_proof.verify(&pp)? {
                    println!("✓ Proof {proof_id} verified");
                } else {
                    println!("✗ Proof {proof_id} failed on verification");
                }
            }
        }
        Ok(())
    }
}

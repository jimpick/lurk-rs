use serde::{Deserialize, Serialize};

#[cfg(not(target_arch = "wasm32"))]
use anyhow::Result;

use lurk::{
    eval::{
        lang::{Coproc, Lang},
        Status,
    },
    field::{LanguageField, LurkField},
    proof::nova,
    z_ptr::ZExprPtr,
    z_store::ZStore,
};

#[cfg(not(target_arch = "wasm32"))]
use lurk::public_parameters::public_params;

type F = pasta_curves::pallas::Scalar; // TODO: generalize this

/// Minimal data structure containing just enough for proof verification
#[derive(Serialize, Deserialize)]
pub enum LurkProof<'a> {
    Nova {
        proof: nova::Proof<'a, Coproc<F>>,
        public_inputs: Vec<F>,
        public_outputs: Vec<F>,
        num_steps: usize,
        field: LanguageField,
        rc: usize,
        lang: Lang<F, Coproc<F>>,
    },
}

/// Carries extra information to help with visualization, experiments etc
#[derive(Serialize, Deserialize)]
pub struct LurkProofMeta<F: LurkField> {
    pub field: LanguageField,
    pub iterations: usize,
    pub evaluation_cost: u128,
    pub generation_cost: u128,
    pub compression_cost: u128,
    pub status: Status,
    pub expression: ZExprPtr<F>,
    pub environment: ZExprPtr<F>,
    pub result: ZExprPtr<F>,
    pub zstore: ZStore<F>,
}

impl<'a> LurkProof<'a> {
    #[cfg(not(target_arch = "wasm32"))]
    pub fn verify_proof(proof_id: &str) -> Result<()> {
        use super::paths::proof_path;
        use crate::cli::repl::Backend;
        use log::info;
        use std::{fs::File, io::BufReader, sync::Arc};

        let file = File::open(proof_path(proof_id))?;
        let lurk_proof: LurkProof = bincode::deserialize_from(BufReader::new(file))?;
        match lurk_proof {
            Self::Nova {
                proof,
                public_inputs,
                public_outputs,
                num_steps,
                field,
                rc,
                lang,
            } => {
                Backend::Nova.validate_field(&field)?;

                info!("Loading public parameters");
                let pp = public_params(rc, Arc::new(lang))?;

                if proof.verify(&pp, num_steps, &public_inputs, &public_outputs)? {
                    println!("✓ Proof {proof_id} verified");
                } else {
                    println!("✗ Proof {proof_id} failed on verification");
                }
            }
        }
        Ok(())
    }
}

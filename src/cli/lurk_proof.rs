use serde::{Deserialize, Serialize};

#[cfg(not(target_arch = "wasm32"))]
use anyhow::Result;

use lurk::{
    eval::{
        lang::{Coproc, Lang},
        Status,
    },
    proof::nova,
};

#[cfg(not(target_arch = "wasm32"))]
use lurk::proof::nova::PublicParams;

type F = pasta_curves::pallas::Scalar;

#[derive(Serialize, Deserialize)]
pub struct ProofInfo {
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

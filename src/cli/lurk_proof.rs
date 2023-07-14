use serde::{Deserialize, Serialize};

#[cfg(not(target_arch = "wasm32"))]
use anyhow::Result;

use lurk::{
    eval::lang::{Coproc, Lang},
    proof::nova,
};

#[cfg(not(target_arch = "wasm32"))]
use lurk::proof::nova::PublicParams;

type F = pasta_curves::pallas::Scalar;

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
pub enum LurkProofMeta {
    Evaluation {
        input: Option<String>,
        environment: Option<String>,
        output: Option<String>,
    },
    Opening {
        input: Option<String>,
        output: Option<String>,
    },
}

#[derive(Serialize, Deserialize)]
pub struct LurkProofInfo {
    pub rc: usize,
    pub lang: Lang<F, Coproc<F>>,
    pub iterations: usize,
    pub generation_cost: u128,
    pub compression_cost: u128,
}

#[derive(Serialize, Deserialize)]
pub enum LurkProof<'a> {
    Nova {
        proof: NovaProof<'a>,
        info: LurkProofInfo,
        meta: LurkProofMeta,
    },
}

impl<'a> LurkProof<'a> {
    #[inline]
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn new_nova(proof: NovaProof<'a>, info: LurkProofInfo, meta: LurkProofMeta) -> Self {
        Self::Nova { proof, info, meta }
    }
}

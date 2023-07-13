use serde::{Deserialize, Serialize};

use anyhow::Result;

use lurk::{
    eval::lang::{Coproc, Lang},
    proof::{nova, nova::PublicParams},
};

type F = pasta_curves::pallas::Scalar;

#[derive(Serialize, Deserialize)]
pub struct NovaProof<'a> {
    pub proof: nova::Proof<'a, Coproc<F>>,
    pub public_inputs: Vec<F>,
    pub public_outputs: Vec<F>,
    pub num_steps: usize,
}

impl<'a> NovaProof<'a> {
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
        input: String,
        environment: String,
        output: String,
    },
    Opening {
        input: String,
        output: String,
    },
}

#[derive(Serialize, Deserialize)]
pub struct LurkProofInfo {
    pub rc: usize,
    pub lang: Lang<F, Coproc<F>>,
    pub iterations: usize,
    pub cost: u128,
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
    pub(crate) fn new_nova(proof: NovaProof<'a>, info: LurkProofInfo, meta: LurkProofMeta) -> Self {
        Self::Nova { proof, info, meta }
    }
}

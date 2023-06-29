use abomonation::decode;
use std::fs::File;
use std::io::{self, BufReader, BufWriter};
use std::path::Path;
use std::sync::Arc;

use crate::coprocessor::Coprocessor;
use crate::{
    eval::lang::Lang,
    proof::nova::{self, PublicParams},
};
use pasta_curves::pallas;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub mod error;
pub mod file_map;
mod registry;

use crate::public_parameters::error::Error;

pub type S1 = pallas::Scalar;

pub fn public_params<C: Coprocessor<S1> + Serialize + DeserializeOwned + 'static>(
    rc: usize,
    abomonated: bool,
    lang: Arc<Lang<S1, C>>,
) -> Result<Arc<PublicParams<'static, C>>, Error>
where
    C: Coprocessor<S1> + Serialize + DeserializeOwned + 'static,
{
    let f = |lang: Arc<Lang<S1, C>>| Arc::new(nova::public_params(rc, lang));
    registry::CACHE_REG.get_coprocessor_or_update_with(rc, abomonated, f, lang)
}

/// Attempts to extract abomonated public parameters.
/// To avoid all copying overhead, we zerocopy all of the data within the file;
/// this leads to extremely high performance, but restricts the lifetime of the data
/// to the lifetime of the file. Thus, we cannot pass a reference out and must
/// rely on a closure to capture the data and continue the computation in `bind`.
pub fn with_public_params<C, F, T>(rc: usize, lang: Arc<Lang<S1, C>>, bind: F) -> Result<T, Error>
where
    C: Coprocessor<S1> + Serialize + DeserializeOwned + 'static,
    F: FnOnce(&PublicParams<'static, C>) -> T,
{
    let disk_cache = file_map::FileIndex::new("public_params").unwrap();
    // use the cached language key
    let lang_key = lang.key();
    // Sanity-check: we're about to use a lang-dependent disk cache, which should be specialized
    // for this lang/coprocessor.
    let key = format!("public-params-rc-{rc}-coproc-{lang_key}-abomonated");

    match disk_cache.get_raw_bytes(&key) {
        Ok(mut bytes) => {
            if let Some((pp, remaining)) = unsafe { decode(&mut bytes) } {
                assert!(remaining.is_empty());
                eprintln!("Using disk-cached public params for lang {}", lang_key);
                Ok(bind(pp))
            } else {
                eprintln!("failed to decode bytes");
                let pp = nova::public_params(rc, lang);
                let mut bytes = Vec::new();
                unsafe { abomonation::encode(&pp, &mut bytes)? };
                // maybe just directly write
                disk_cache
                    .set_abomonated(&key, &pp)
                    .map_err(|e| Error::CacheError(format!("Disk write error: {e}")))?;
                Ok(bind(&pp))
            }
        }
        Err(e) => {
            eprintln!("{e}");
            let pp = nova::public_params(rc, lang);
            // maybe just directly write
            disk_cache
                .set_abomonated(&key, &pp)
                .map_err(|e| Error::CacheError(format!("Disk write error: {e}")))?;
            Ok(bind(&pp))
        }
    }
}
pub trait FileStore
where
    Self: Sized,
{
    fn write_to_path<P: AsRef<Path>>(&self, path: P);
    fn write_to_json_path<P: AsRef<Path>>(&self, path: P);
    fn read_from_path<P: AsRef<Path>>(path: P) -> Result<Self, Error>;
    fn read_from_json_path<P: AsRef<Path>>(path: P) -> Result<Self, Error>;
    fn read_from_stdin() -> Result<Self, Error>;
}

impl<T: Serialize> FileStore for T
where
    for<'de> T: Deserialize<'de>,
{
    fn write_to_path<P: AsRef<Path>>(&self, path: P) {
        let file = File::create(path).expect("failed to create file");
        let writer = BufWriter::new(&file);

        bincode::serialize_into(writer, &self).expect("failed to write file");
    }

    fn write_to_json_path<P: AsRef<Path>>(&self, path: P) {
        let file = File::create(path).expect("failed to create file");
        let writer = BufWriter::new(&file);

        serde_json::to_writer(writer, &self).expect("failed to write file");
    }

    fn read_from_path<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        bincode::deserialize_from(reader).map_err(|e| Error::CacheError(format!("{}", e)))
    }

    fn read_from_json_path<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        Ok(serde_json::from_reader(reader)?)
    }

    fn read_from_stdin() -> Result<Self, Error> {
        let reader = BufReader::new(io::stdin());
        Ok(serde_json::from_reader(reader).expect("failed to read from stdin"))
    }
}

use std::fs::{create_dir_all, File};
use std::io::{BufReader, Error, BufWriter, Write, Read};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::time::Instant;

use rkyv::de::deserializers::SharedDeserializeMap;
use rkyv::Archive;
use rkyv::ser::serializers::AllocSerializer;

use crate::public_parameters::FileStore;

pub(crate) fn data_dir() -> PathBuf {
    match std::env::var("FCOMM_DATA_PATH") {
        Ok(name) => name.into(),
        Err(_) => PathBuf::from("/var/tmp/fcomm_data/"),
    }
}

pub(crate) struct FileIndex<K: ToString> {
    dir: PathBuf,
    _t: PhantomData<K>,
}

impl<K: ToString> FileIndex<K> {
    pub(crate) fn new<P: AsRef<Path>>(name: P) -> Result<Self, Error> {
        let data_dir = data_dir();
        let dir = PathBuf::from(&data_dir).join(name.as_ref());
        create_dir_all(&dir)?;

        Ok(Self {
            dir,
            _t: Default::default(),
        })
    }

    fn key_path(&self, key: &K) -> PathBuf {
        self.dir.join(PathBuf::from(key.to_string()))
    }

    pub(crate) fn get<V: FileStore>(&self, key: &K) -> Option<V> {
        self.key_path(key);
        V::read_from_path(self.key_path(key)).ok()
    }

    pub(crate) fn get_archived<V: Archive>(&self, key: &K) -> Option<V>
    where
        <V as Archive>::Archived: rkyv::Deserialize<V, SharedDeserializeMap>,
    {
        let start = Instant::now();
        let file = File::open(self.key_path(key)).ok()?;
        let mut bytes = Vec::new();
        let mut reader = BufReader::new(file);
        reader.read_to_end(&mut bytes).unwrap();
        let read = start.elapsed();
        println!("reading archived takes: {:?}", read);

        let deserialize = unsafe {
            rkyv::from_bytes_unchecked::<V>(&bytes)
                .expect("get_archived failed to deserialize")
        };
        let de = start.elapsed();
        println!("deserializing archived takes: {:?}", de - read);
        Some(deserialize)
    }

    pub(crate) fn set<V: FileStore>(&self, key: K, data: &V) -> Result<(), Error> {
        data.write_to_path(self.key_path(&key));
        Ok(())
    }

    pub(crate) fn set_archived<V: Archive, const N: usize>(&self, key: &K, data: &V) -> Result<(), Error> 
    where V: rkyv::Serialize<AllocSerializer<N>>
    {
        let mut file = File::create(self.key_path(key)).expect("failed to create file");
        let bytes = rkyv::to_bytes(data).expect("set_archived failed to serialize");
        file.write_all(&bytes)?;
        Ok(())
    }
}

pub struct FileMap<K: ToString, V: FileStore> {
    dir: PathBuf,
    _t: PhantomData<(K, V)>,
}

impl<K: ToString, V: FileStore> FileMap<K, V> {
    pub fn new<P: AsRef<Path>>(name: P) -> Result<Self, Error> {
        let data_dir = data_dir();
        let dir = PathBuf::from(&data_dir).join(name.as_ref());
        create_dir_all(&dir)?;

        Ok(Self {
            dir,
            _t: Default::default(),
        })
    }

    fn key_path(&self, key: &K) -> PathBuf {
        self.dir.join(PathBuf::from(key.to_string()))
    }

    pub fn get(&self, key: &K) -> Option<V> {
        self.key_path(key);
        V::read_from_path(self.key_path(key)).ok()
    }

    pub fn set(&self, key: K, data: &V) -> Result<(), Error> {
        data.write_to_path(self.key_path(&key));
        Ok(())
    }
}

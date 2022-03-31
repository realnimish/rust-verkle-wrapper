use std::collections::HashMap;
use std::slice;
use std::convert::TryFrom;
use std::mem::transmute;
use verkle_db::RocksDb;
use verkle_db::{BareMetalDiskDb, BareMetalKVDb, BatchDB, BatchWriter};
use verkle_trie::database::generic::GenericBatchDB;
use verkle_trie::database::generic::GenericBatchWriter;
use verkle_trie::database::memory_db::MemoryDb;
use verkle_trie::database::{
    BranchChild, BranchMeta, Flush, ReadOnlyHigherDb, StemMeta, WriteOnlyHigherDb,
};


pub struct VerkleReadOnlyDiskDb<Storage: 'static> {
    // The underlying key value database
    // We will not be updating this
    pub db: &'static mut GenericBatchDB<Storage>,
    // This stores the key-value pairs that we need to insert into the storage
    pub temp: HashMap<[u8; 32], [u8; 32]>,
}


impl<S: BareMetalDiskDb> VerkleReadOnlyDiskDb<S> {
    pub fn from_db(db: &'static mut GenericBatchDB<S>) -> Self {
        VerkleReadOnlyDiskDb {
            db,
            temp: HashMap::new(),
        }
    }

    pub fn new(db: &'static mut Self) -> Self {
        VerkleReadOnlyDiskDb { 
            db: db, 
            temp: HashMap::new(), 
        }
    }
}


impl<S: BareMetalDiskDb> BareMetalDiskDb for VerkleReadOnlyDiskDb<S> {
    fn from_path<P: AsRef<std::path::Path>>(path: P) -> Self {
        let _db: GenericBatchDB<S> = GenericBatchDB::from_path(path);
        let db: &mut GenericBatchDB<S> = unsafe { transmute(Box::new(_db)) };
        VerkleReadOnlyDiskDb {
            db,
            temp: HashMap::new(),
        }
    }

    const DEFAULT_PATH: &'static str = S::DEFAULT_PATH;
}


impl<S: BareMetalKVDb + BareMetalDiskDb> BareMetalKVDb for VerkleReadOnlyDiskDb<S>  {
    fn fetch(&self, key: &[u8]) -> Option<Vec<u8>> {
        if let Some(val) = self.temp.get(key) {
            return Some(val.to_vec());
        }
        self.db.inner.fetch(key)
    }
    // Create a database given the default path
    fn new() -> Self {
        Self::from_path(Self::DEFAULT_PATH)
    }
}

impl<S: BatchDB> Flush for VerkleReadOnlyDiskDb<S> {
    fn flush(&mut self) {}
}

// impl<S: BareMetalKVDb> ReadOnlyHigherDb for VerkleReadOnlyDiskDb<S> {

// }

// impl<S> WriteOnlyHigherDb for VerkleReadOnlyDiskDb<S> {

// }

pub struct MemoryBatchDB {
    pub(crate) inner: HashMap<[u8; 32], [u8; 32]>
}

impl MemoryBatchDB {
    pub fn new() -> Self {
        MemoryBatchDB {
            inner: HashMap::new()
        }
    }
}

impl BatchWriter for MemoryBatchDB {
    fn new() -> Self {
        MemoryBatchDB::new()
    }

    fn batch_put(&mut self, key: &[u8], val: &[u8]) {
        self.inner.insert(<[u8; 32]>::try_from(key).unwrap(), <[u8; 32]>::try_from(val).unwrap());
    }
}

impl<S: BatchDB> BatchDB for VerkleReadOnlyDiskDb<S> {
    type BatchWrite = MemoryBatchDB;

    fn flush(&mut self, batch: Self::BatchWrite) {
        self.temp.extend(batch.inner.into_iter());
    }
}
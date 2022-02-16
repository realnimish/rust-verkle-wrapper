use verkle_db::{
    BareMetalDiskDb, BareMetalKVDb,
    BatchDB, BatchWriter
};
use verkle_trie::{
    Trie,
    config::Config,
    database::VerkleDb,
    committer::test::TestCommitter,
};
use crate::verkle_variants::traits::FFI;
use rocksdb::{DB, WriteBatch};

pub struct RocksDb(DB);
pub struct _WriteBatch(WriteBatch);

impl BareMetalDiskDb for RocksDb {
    fn from_path<P: AsRef<std::path::Path>>(path: P) -> Self {
        let db = DB::open_default(path).unwrap();
        RocksDb(db)
    }

    const DEFAULT_PATH: &'static str = "./db/verkle_db";
}

impl BatchWriter for _WriteBatch {
    fn new() -> Self {
        let write_batch: WriteBatch = WriteBatch::default();
        _WriteBatch(write_batch)
    }

    fn batch_put(&mut self, key: &[u8], val: &[u8]) {
        self.0.put(key, val)
    }
}

impl BatchDB for RocksDb {
    type BatchWrite = _WriteBatch;

    fn flush(&mut self, batch: Self::BatchWrite) {
        self.0.write(batch.0).unwrap();
    }
}

impl BareMetalKVDb for RocksDb {
    fn fetch(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.0.get(key).unwrap()
    }
    // Create a database given the default path
    fn new() -> Self {
        Self::from_path(Self::DEFAULT_PATH)
    }
}

pub type VerkleTrie = Trie<VerkleDb<RocksDb>, TestCommitter>;

impl FFI for VerkleTrie {
    fn verkle_trie_new(path: &str) -> Self {
        let _db = VerkleDb::from_path(path);
        let committer = TestCommitter;
        let config = Config{ db: _db, committer };
        let mut _trie = Trie::new(config);
        _trie
    }
}

use verkle_db::{
    BareMetalDiskDb, BareMetalKVDb,
    BatchDB, BatchWriter, RocksDb
};
use verkle_trie::{
    Trie,
    config::VerkleConfig,
    database::VerkleDb,
    committer::precompute::PrecomputeLagrange,
};
use crate::verkle_variants::traits::FFI;

pub type VerkleTrie = Trie<VerkleDb<RocksDb>, PrecomputeLagrange>;

impl FFI for VerkleTrie {
    fn verkle_trie_new(path: &str) -> Self {
        let _db = VerkleDb::from_path(path);
        let config = match VerkleConfig::new(_db) {
            Ok(cnf) => cnf,
            Err(_) => {
                let _db = VerkleDb::from_path(path);
                VerkleConfig::open(_db).unwrap()
            },
        };
        let mut _trie = Trie::new(config);
        _trie
    }
}

use verkle_db::{
    BareMetalDiskDb, BareMetalKVDb,
    BatchDB, BatchWriter, RocksDb
};
use verkle_trie::{
    Trie,
    config::Config,
    database::VerkleDb,
    committer::test::TestCommitter,
};
use crate::verkle_variants::traits::FFI;

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

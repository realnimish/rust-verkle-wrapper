use verkle_trie::{
    database::memory_db::MemoryDb,
    trie::Trie
};
use verkle_trie::committer::precompute::PrecomputeLagrange;
use verkle_trie::config::VerkleConfig;
use crate::verkle_variants::traits::*;

pub type VerkleTrie = Trie<MemoryDb, PrecomputeLagrange>;

impl FFI for VerkleTrie {

    fn verkle_trie_new() -> Self {
        let _db = MemoryDb::new();
        let config = VerkleConfig::new(_db);
        let mut _trie = Trie::new(config);
        _trie
    }
}
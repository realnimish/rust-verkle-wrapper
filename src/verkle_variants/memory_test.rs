use verkle_trie::{
    database::memory_db::MemoryDb,
    trie::Trie
};
use verkle_trie::committer::test::TestCommitter;
use verkle_trie::config::Config;
use crate::verkle_variants::traits::*;

pub type VerkleTrie = Trie<MemoryDb, TestCommitter>;

impl FFI for VerkleTrie {
    fn verkle_trie_new() -> Self {
        let _db = MemoryDb::new();
        let committer = TestCommitter;
        let config = Config{ db: _db, committer };
        let mut _trie = Trie::new(config);
        _trie
    }
}
use verkle_trie::{
    database::memory_db::MemoryDb,
    trie::Trie
};
use verkle_trie::committer::test::TestCommitter;
use verkle_trie::config::Config;
use crate::verkle_variants::traits::*;

type Model = Trie<MemoryDb, TestCommitter>;

pub struct VerkleTrie {
    trie: Model,
}

impl VerkleGroup<Model> for VerkleTrie {
    fn trie(&mut self) -> &mut Model {
        &mut self.trie
    }
}

impl FFI<Model> for VerkleTrie {
    type VerkleTrie = VerkleTrie;

    fn verkle_trie_new() -> VerkleTrie {
        let _db = MemoryDb::new();
        let committer = TestCommitter;
        let config = Config{ db: _db, committer };
        let mut _trie = Trie::new(config);
        let vt = VerkleTrie{ trie: _trie };
        vt
    }
}
use std::collections::HashMap;
use std::mem::transmute;
use verkle_trie::database::memory_db::MemoryDb;
use verkle_trie::database::{
    BranchChild, BranchMeta, Flush, ReadOnlyHigherDb, StemMeta, WriteOnlyHigherDb,
};

// All nodes at this level or above will be cached in memory
const CACHE_DEPTH: u8 = 4;

pub struct VerkleMemoryDb {
    // The underlying key value database - use this for test
    // We try to avoid fetching from this, and we only store at the end of a batch insert
    pub storage: &'static mut MemoryDb,
    // This stores the key-value pairs that we need to insert into the storage
    // This is flushed after every batch insert
    pub batch: MemoryDb,
    // This stores the top 3 layers of the trie, since these are the most accessed
    // in the trie on average
    pub cache: MemoryDb,
}

impl VerkleMemoryDb {
    pub fn new(storage: &'static mut MemoryDb) -> Self {
        VerkleMemoryDb {
            storage,
            batch: MemoryDb::new(),
            cache: MemoryDb::new(),
        }
    }

    pub fn new_db() -> Self {
        let db: &mut MemoryDb = unsafe { transmute(Box::new(MemoryDb::new())) };
        VerkleMemoryDb {
            storage: db,
            batch: MemoryDb::new(),
            cache: MemoryDb::new(),
        }
    }
}

impl ReadOnlyHigherDb for VerkleMemoryDb {
    fn get_leaf(&self, key: [u8; 32]) -> Option<[u8; 32]> {
        // First try to get it from cache
        if let Some(val) = self.cache.get_leaf(key) {
            return Some(val);
        }
        // Now try to get it from batch
        if let Some(val) = self.batch.get_leaf(key) {
            return Some(val);
        }
        // Now try the disk
        self.storage.get_leaf(key)
    }

    fn get_stem_meta(&self, stem_key: [u8; 31]) -> Option<StemMeta> {
        // First try to get it from cache
        if let Some(val) = self.cache.get_stem_meta(stem_key) {
            return Some(val);
        }
        // Now try to get it from batch
        if let Some(val) = self.batch.get_stem_meta(stem_key) {
            return Some(val);
        }
        // Now try the disk
        self.storage.get_stem_meta(stem_key)
    }

    fn get_branch_meta(&self, key: &[u8]) -> Option<BranchMeta> {
        // First try to get it from cache
        if let Some(val) = self.cache.get_branch_meta(key) {
            return Some(val);
        }
        // Now try to get it from batch
        if let Some(val) = self.batch.get_branch_meta(key) {
            return Some(val);
        }
        // Now try the disk
        self.storage.get_branch_meta(key)
    }

    fn get_branch_child(&self, branch_id: &[u8], index: u8) -> Option<BranchChild> {
        // First try to get it from cache
        if let Some(val) = self.cache.get_branch_child(branch_id, index) {
            return Some(val);
        }
        // Now try to get it from batch
        if let Some(val) = self.batch.get_branch_child(branch_id, index) {
            return Some(val);
        }
        // Now try the disk
        self.storage.get_branch_child(branch_id, index)
    }

    fn get_branch_children(&self, branch_id: &[u8]) -> Vec<(u8, BranchChild)> {
        // Check the depth. If the branch is at CACHE_DEPTH or lower, then it will be in the cache
        // TODO this assumes that the cache is populated on startup from disk
        if branch_id.len() as u8 <= CACHE_DEPTH {
            return self.cache.get_branch_children(branch_id);
        }
        // First get the children from storage
        let mut children: HashMap<_, _> = self
            .storage
            .get_branch_children(branch_id)
            .into_iter()
            .map(|(index, val)| (index, val))
            .collect();
        //
        // Then get the children from the batch
        let children_from_batch = self.batch.get_branch_children(branch_id);
        //
        // Now insert the children from batch into the storage children as they will be fresher
        // overwriting if they have the same indices
        for (index, val) in children_from_batch {
            children.insert(index, val);
        }
        children
            .into_iter()
            .map(|(index, val)| (index, val))
            .collect()
    }

    fn get_stem_children(&self, stem_key: [u8; 31]) -> Vec<(u8, [u8; 32])> {
        // Stems don't have a depth, however the children for all stem will always be on the same depth
        // If we get any children for the stem in the cache storage, then this means we have collected all of them
        // TODO this assumes that the cache is populated on startup from disk
        let children = self.cache.get_stem_children(stem_key);
        if !children.is_empty() {
            return children;
        }

        // It's possible that they are in disk storage and that batch storage has some recent updates
        // First get the children from storage
        let mut children: HashMap<_, _> = self
            .storage
            .get_stem_children(stem_key)
            .into_iter()
            .map(|(index, val)| (index, val))
            .collect();
        //
        // Then get the children from the batch
        let children_from_batch = self.batch.get_stem_children(stem_key);
        //
        // Now insert the children from batch into the storage children as they will be fresher
        // overwriting if they have the same indices
        for (index, val) in children_from_batch {
            children.insert(index, val);
        }
        children
            .into_iter()
            .map(|(index, val)| (index, val))
            .collect()
    }
}

// Always save in the permanent storage and only save in the memorydb if the depth is <= cache depth
impl WriteOnlyHigherDb for VerkleMemoryDb {
    fn insert_leaf(&mut self, key: [u8; 32], value: [u8; 32], depth: u8) -> Option<Vec<u8>> {
        if depth <= CACHE_DEPTH {
            self.cache.insert_leaf(key, value, depth);
        }
        self.batch.insert_leaf(key, value, depth)
    }

    fn insert_stem(&mut self, key: [u8; 31], meta: StemMeta, depth: u8) -> Option<StemMeta> {
        if depth <= CACHE_DEPTH {
            self.cache.insert_stem(key, meta, depth);
        }
        self.batch.insert_stem(key, meta, depth)
    }

    fn add_stem_as_branch_child(
        &mut self,
        branch_child_id: Vec<u8>,
        stem_id: [u8; 31],
        depth: u8,
    ) -> Option<BranchChild> {
        if depth <= CACHE_DEPTH {
            self.cache
                .add_stem_as_branch_child(branch_child_id.clone(), stem_id, depth);
        }
        self.batch
            .add_stem_as_branch_child(branch_child_id, stem_id, depth)
    }

    fn insert_branch(&mut self, key: Vec<u8>, meta: BranchMeta, depth: u8) -> Option<BranchMeta> {
        if depth <= CACHE_DEPTH {
            self.cache.insert_branch(key.clone(), meta, depth);
        }
        self.batch.insert_branch(key, meta, depth)
    }
}

impl Flush for VerkleMemoryDb {
    fn flush(&mut self) {
        let now = std::time::Instant::now();

        for (key, value) in self.batch.leaf_table.iter() {
            self.storage.insert_leaf(*key, *value, 0);
        }

        for (key, meta) in self.batch.stem_table.iter() {
            self.storage.insert_stem(*key, *meta, 0);
        }

        for (branch_id, b_child) in self.batch.branch_table.iter() {
            let branch_id = branch_id.clone();
            match b_child {
                BranchChild::Stem(stem_id) => {
                    self.storage
                        .add_stem_as_branch_child(branch_id, *stem_id, 0);
                }
                BranchChild::Branch(b_meta) => {
                    self.storage.insert_branch(branch_id, *b_meta, 0);
                }
            };
        }

        let num_items = self.batch.num_items();
        println!(
            "write to batch time: {}, item count : {}",
            now.elapsed().as_millis(),
            num_items
        );

        self.batch.clear();
    }
}

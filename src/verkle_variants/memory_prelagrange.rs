use verkle_trie::{
    database::memory_db::MemoryDb,
    trie::Trie
};
use verkle_trie::committer::precompute::PrecomputeLagrange;
use verkle_trie::config::VerkleConfig;
use crate::verkle_variants::traits::FFI;

pub type VerkleTrie = Trie<MemoryDb, PrecomputeLagrange>;

impl FFI for VerkleTrie {

    fn verkle_trie_new(_path: &str) -> Self {
        let _db = MemoryDb::new();
        let config = match VerkleConfig::new(_db) {
            Ok(cnf) => cnf,
            Err(_) => {
                let _db = MemoryDb::new();
                VerkleConfig::open(_db).unwrap()
            },
        };
        let mut _trie = Trie::new(config);
        _trie
    }
}

#[cfg(test)]
mod tests {
    /*
    * Check if we need to ensure that the `precomputed_points.bin` file
    * is generated safely as the tests are run in parallel
    */
    use super::*;
    use crate::get_array_from_slice_argument;
    use std::mem::transmute;
    
    #[test]
    fn root_hash() {
        let mut trie = VerkleTrie::verkle_trie_new();
        let hash_ptr = trie.get_root_hash();
        let hash = get_array_from_slice_argument(hash_ptr);
        assert_eq!(hash, [0u8; 32]);
    }

    #[test]
    fn insert_fetch() {
        let mut trie = VerkleTrie::verkle_trie_new();

        let _one:[u8;32] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ];
        let one: *const u8  = unsafe {transmute(Box::new(_one))};
        let _one_32:[u8;32] = [1; 32];
        let one_32 = unsafe {transmute(Box::new(_one_32))};
        trie.verkle_trie_insert(one, one);
        trie.verkle_trie_insert(one_32, one);
        let val = trie.verkle_trie_get(one_32);
        let _val: Box<[u8;32]> = unsafe { transmute(val)};
        let result = * _val;
        assert_eq!(result, _one);
    }

    #[test]
    fn insert_account_fetch() {
        let mut trie = VerkleTrie::verkle_trie_new();

        let tree_key_version:[u8;32] = [ 121, 85, 7, 198, 131, 230, 143, 90, 165, 129, 173, 81, 186,
            89, 19, 191, 13, 107, 197, 120, 243, 229, 224, 183, 72, 25, 6, 8, 210, 159, 31, 0];

        let tree_key_balance:[u8;32] = [ 121, 85, 7, 198, 131, 230, 143, 90, 165, 129, 173, 81, 186,
            89, 19, 191, 13, 107, 197, 120, 243, 229, 224, 183, 72, 25, 6, 8, 210, 159, 31, 1];

        let tree_key_nonce:[u8;32] = [ 121, 85, 7, 198, 131, 230, 143, 90, 165, 129, 173, 81, 186,
            89, 19, 191, 13, 107, 197, 120, 243, 229, 224, 183, 72, 25, 6, 8, 210, 159, 31, 2];

        let tree_key_code_keccak:[u8;32] = [ 121, 85, 7, 198, 131, 230, 143, 90, 165, 129, 173, 81,
            186, 89, 19, 191, 13, 107, 197, 120, 243, 229, 224, 183, 72, 25, 6, 8, 210, 159, 31, 3];

        let tree_key_code_size:[u8;32] = [ 121, 85, 7, 198, 131, 230, 143, 90, 165, 129, 173, 81,
            186, 89, 19, 191, 13, 107, 197, 120, 243, 229, 224, 183, 72, 25, 6, 8, 210, 159, 31, 4];

        let empty_code_hash_value:[u8;32] = [ 197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178,
            220, 199, 3, 192, 229, 0, 182, 83, 202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112];

        let value_0:[u8;32] = [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0];

        let value_2:[u8;32] = [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 2];


        trie.verkle_trie_insert(
            unsafe {transmute(Box::new(tree_key_version))},
            unsafe {transmute(Box::new(value_0))}
        );

        trie.verkle_trie_insert(
            unsafe {transmute(Box::new(tree_key_balance))},
            unsafe {transmute(Box::new(value_2))}
        );

        trie.verkle_trie_insert(
            unsafe {transmute(Box::new(tree_key_nonce))},
            unsafe {transmute(Box::new(value_0))}
        );

        trie.verkle_trie_insert(
            unsafe {transmute(Box::new(tree_key_code_keccak))},
            unsafe {transmute(Box::new(empty_code_hash_value))}
        );

        trie.verkle_trie_insert(
            unsafe {transmute(Box::new(tree_key_code_size))},
            unsafe {transmute(Box::new(value_0))}
        );

        let val = trie.verkle_trie_get(unsafe {transmute(Box::new(tree_key_version))});
        assert!(!val.is_null());
        let val = trie.verkle_trie_get(unsafe {transmute(Box::new(tree_key_balance))});
        assert!(!val.is_null());
        let val = trie.verkle_trie_get(unsafe {transmute(Box::new(tree_key_nonce))});
        assert!(!val.is_null());
        let val = trie.verkle_trie_get(unsafe {transmute(Box::new(tree_key_code_keccak))});
        assert!(!val.is_null());
        let val = trie.verkle_trie_get(unsafe {transmute(Box::new(tree_key_code_size))});
        assert!(!val.is_null());
    }

    #[test]
    fn gen_verify_proof() {
        let mut trie = VerkleTrie::verkle_trie_new();

        let _one:[u8;32] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ];
        let one: *const u8  = unsafe {transmute(Box::new(_one))};
        let _one_32:[u8;32] = [1; 32];
        let one_32 = unsafe {transmute(Box::new(_one_32))};
        trie.verkle_trie_insert(one, one);
        trie.verkle_trie_insert(one_32, one);
        let _proof = trie.get_verkle_proof(one);
        let proof = unsafe{&mut *_proof};
        let verif = trie.verify_verkle_proof(proof.ptr, proof.len, one, one);
        assert_eq!(verif, 1);
        let verif = trie.verify_verkle_proof(proof.ptr, proof.len, one, one_32);
        assert_eq!(verif, 0);
    }

    #[test]
    fn generate_proof_test(){
        let mut trie = VerkleTrie::verkle_trie_new();

        let tree_key_version:[u8;32] = [ 121, 85, 7, 198, 131, 230, 143, 90, 165, 129, 173, 81, 186,
            89, 19, 191, 13, 107, 197, 120, 243, 229, 224, 183, 72, 25, 6, 8, 210, 159, 31, 0];

        let tree_key_balance:[u8;32] = [ 121, 85, 7, 198, 131, 230, 143, 90, 165, 129, 173, 81, 186,
            89, 19, 191, 13, 107, 197, 120, 243, 229, 224, 183, 72, 25, 6, 8, 210, 159, 31, 1];

        let tree_key_nonce:[u8;32] = [ 121, 85, 7, 198, 131, 230, 143, 90, 165, 129, 173, 81, 186,
            89, 19, 191, 13, 107, 197, 120, 243, 229, 224, 183, 72, 25, 6, 8, 210, 159, 31, 2];

        let tree_key_code_keccak:[u8;32] = [ 121, 85, 7, 198, 131, 230, 143, 90, 165, 129, 173, 81,
            186, 89, 19, 191, 13, 107, 197, 120, 243, 229, 224, 183, 72, 25, 6, 8, 210, 159, 31, 3];

        let tree_key_code_size:[u8;32] = [ 121, 85, 7, 198, 131, 230, 143, 90, 165, 129, 173, 81,
            186, 89, 19, 191, 13, 107, 197, 120, 243, 229, 224, 183, 72, 25, 6, 8, 210, 159, 31, 4];
        
        let empty_code_hash_value:[u8;32] = [ 197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178,
            220, 199, 3, 192, 229, 0, 182, 83, 202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112];

        let value_0:[u8;32] = [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0];

        let value_2:[u8;32] = [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 2];

        let all_keys = vec![tree_key_version, tree_key_balance, tree_key_nonce, tree_key_code_keccak, tree_key_code_size];
        let all_vals = vec![value_0, value_2, value_0, empty_code_hash_value, value_0];

        trie.verkle_trie_insert_multiple(all_keys.as_ptr(), all_vals.as_ptr(), all_keys.len());

        let mut _proof = trie.get_verkle_proof_multiple(all_keys.as_ptr(), all_keys.len());
        let proof = unsafe{&mut *_proof};
        let verification = trie.verify_verkle_proof_multiple(proof.ptr, proof.len, all_keys.as_ptr(), all_vals.as_ptr(), all_keys.len());
        assert_eq!(verification, 1);
    }
}

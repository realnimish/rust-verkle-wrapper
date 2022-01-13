use std::ptr;
use std::mem::transmute;
use std::slice;

extern crate verkle_trie;

use ark_ec::ProjectiveCurve;
use once_cell::sync::Lazy;
use std::convert::TryInto;
use verkle_db::{BareMetalDiskDb};
use verkle_trie::{database::{memory_db::MemoryDb, VerkleDb}, trie::Trie, Value};
use verkle_trie::committer::precompute::PrecomputeLagrange;
use verkle_trie::config::{VerkleConfig};
use verkle_trie::database::ReadWriteHigherDb;
use verkle_trie::TrieTrait;

#[repr(C)]
pub struct VerkleTrie {
    trie: Trie<MemoryDb, PrecomputeLagrange>,
}


pub extern fn get_verkle_trie() -> Trie<MemoryDb, PrecomputeLagrange> {
    let _db = MemoryDb::new();
    let config = VerkleConfig::new(_db);
    let mut _trie = Trie::new(config);
    _trie
}

#[no_mangle]
pub extern fn verkle_trie_new() -> *mut VerkleTrie {

    let _db = MemoryDb::new();
    let config = VerkleConfig::new(_db);
    let mut _trie = Trie::new(config);
    let mut vt = VerkleTrie {
        trie: _trie,
    };
    let ret = unsafe { transmute (Box::new(vt))};
    ret
}

#[no_mangle]
pub extern fn verkle_trie_get(vt: *mut VerkleTrie, key: *const u8) -> *const u8 {
    let mut _vt = unsafe { &mut * vt };
    let _key = get_array_from_slice_argument(key);
    let _result = &_vt.trie.get(_key);
    match _result {
        Some(x) => {
            let _result = unsafe { transmute ( Box::new(*x))};
            _result
        }
        None  => ptr::null(),
    }
}

#[no_mangle]
pub extern fn verkle_trie_insert(vt: *mut VerkleTrie, key: *const u8, value: *const u8) {
    let mut _vt = unsafe { &mut * vt };
    let _key = get_array_from_slice_argument(key);
    let _value = get_array_from_slice_argument(value);
    let _iterator = vec![(_key,_value)];
    &_vt.trie.insert(_iterator.into_iter());
}
//
// #[no_mangle]
// pub extern fn verkle_trie_create_path(trie: *mut VerkleTrie<'static>, key: *const u8) -> *mut VerklePath {
//     let mut _trie = unsafe { &mut * trie};
//     let _key = Key::from_arr(get_array_from_slice_argument(key));
//     let _verkle_path = unsafe { transmute( Box::new( _trie.create_verkle_path( &_key ).unwrap() ) ) };
//     _verkle_path
// }
//
// #[no_mangle]
// pub extern fn verkle_trie_create_proof(path: *mut VerklePath, keys: *mut SetupKeys) -> *mut VerkleProof {
//     let mut _path = unsafe { &mut * path};
//     let mut _keys = unsafe { &mut * keys };
//     let _commit_key = &_keys.commit_key;
//     let _verkle_proof = unsafe { transmute( Box::new( _path.create_proof( _commit_key ) ) ) };
//     _verkle_proof
// }
//
// #[no_mangle]
// pub extern fn verkle_trie_verify(proof: *mut VerkleProof, path: *mut VerklePath, keys: *mut SetupKeys) -> bool {
//     let mut _proof = unsafe { &mut * proof};
//     let mut _path = unsafe { &mut * path};
//     let mut _keys = unsafe { &mut * keys };
//     let _opening_key = &_keys.opening_key;
//     let res = _proof.verify(
//         _opening_key,
//         &_path.commitments,
//         &_path.omega_path_indices,
//         &_path.node_roots,
//     );
//     res
// }
//
//
pub fn get_array_from_slice_argument(sl: *const u8) -> [u8; 32] {
    let _raw_slice = unsafe {
        assert!(!sl.is_null());
        slice::from_raw_parts(sl, 32)
    };
    _raw_slice.try_into().expect("slice with incorrect length")
}

#[cfg(test)]
mod tests {
    use crate::verkle_trie_new;
    use crate::verkle_trie_insert;
    use crate::verkle_trie_get;
    use crate::get_array_from_slice_argument;
    use std::mem::transmute;

    #[test]
    fn insert_fetch() {
        let trie = verkle_trie_new();

        let _one:[u8;32] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ];
        let one: *const u8  = unsafe {transmute(Box::new(_one))};
        let _one_32:[u8;32] = [1; 32];
        let one_32 = unsafe {transmute(Box::new(_one_32))};
        verkle_trie_insert(trie, one, one);
        verkle_trie_insert(trie, one_32, one);
        let val = verkle_trie_get(trie, one_32);
        let _val: Box<[u8;32]> = unsafe { transmute(val)};
        let result = * _val;
        assert_eq!(result, _one);
    }

    #[test]
    fn insert_account_fetch() {
        let trie = verkle_trie_new();

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


        verkle_trie_insert(
            trie,
            unsafe {transmute(Box::new(tree_key_version))},
            unsafe {transmute(Box::new(value_0))}
        );

        verkle_trie_insert(
            trie,
            unsafe {transmute(Box::new(tree_key_balance))},
            unsafe {transmute(Box::new(value_2))}
        );

        verkle_trie_insert(
            trie,
            unsafe {transmute(Box::new(tree_key_nonce))},
            unsafe {transmute(Box::new(value_0))}
        );

        verkle_trie_insert(
            trie,
            unsafe {transmute(Box::new(tree_key_code_keccak))},
            unsafe {transmute(Box::new(empty_code_hash_value))}
        );

        verkle_trie_insert(
            trie,
            unsafe {transmute(Box::new(tree_key_code_size))},
            unsafe {transmute(Box::new(value_0))}
        );

        let val = verkle_trie_get(trie, unsafe {transmute(Box::new(tree_key_version))});
        assert!(!val.is_null());
        let val = verkle_trie_get(trie, unsafe {transmute(Box::new(tree_key_balance))});
        assert!(!val.is_null());
        let val = verkle_trie_get(trie, unsafe {transmute(Box::new(tree_key_nonce))});
        assert!(!val.is_null());
        let val = verkle_trie_get(trie, unsafe {transmute(Box::new(tree_key_code_keccak))});
        assert!(!val.is_null());
        let val = verkle_trie_get(trie, unsafe {transmute(Box::new(tree_key_code_size))});
        assert!(!val.is_null());
    }
}

#![feature(vec_into_raw_parts)]
mod verkle_variants;
use std::slice;
use std::mem::transmute;
use std::convert::TryInto;
use verkle_variants::{
    memory_test,
    memory_prelagrange,
    rocksdb_test,
    traits::FFI,
};
use std::ffi::CStr;
use std::os::raw::c_char;

#[repr(C)]
pub enum VerkleTrie {
    MemoryTest(memory_test::VerkleTrie),
    MemoryPrelagrange(memory_prelagrange::VerkleTrie),
    RocksdbTest(rocksdb_test::VerkleTrie),
}

#[repr(C)]
pub struct Proof {
    pub ptr: *const u8,
    pub len: usize,
}

#[repr(C)]
pub enum DatabaseScheme {
    MemoryDb,
    RocksDb,
}

#[repr(C)]
pub enum CommitScheme {
    TestCommitment,
    PrecomputeLagrange,
}

#[no_mangle]
pub extern fn verkle_trie_new(
    database_scheme: DatabaseScheme,
    commit_scheme: CommitScheme,
    db_path: *const c_char
) -> *mut VerkleTrie {

    let db_path = unsafe {
        CStr::from_ptr(db_path)
        .to_str().expect("Invalid pathname")
    };

    let vt = match database_scheme {
        DatabaseScheme::MemoryDb => match commit_scheme {
            CommitScheme::TestCommitment => {
                let _vt = memory_test::VerkleTrie::verkle_trie_new(db_path);
                VerkleTrie::MemoryTest(_vt)
            },
            CommitScheme::PrecomputeLagrange => {
                let _vt = memory_prelagrange::VerkleTrie::verkle_trie_new(db_path);
                VerkleTrie::MemoryPrelagrange(_vt)
            },
        },
        DatabaseScheme::RocksDb => match commit_scheme {
            CommitScheme::TestCommitment => {
                let _vt = rocksdb_test::VerkleTrie::verkle_trie_new(db_path);
                VerkleTrie::RocksdbTest(_vt)
            },
            CommitScheme::PrecomputeLagrange => panic!("Given model not implemented")
        }
    };
    let ret = unsafe { transmute (Box::new(vt))};
    ret
}

#[no_mangle]
pub extern fn verkle_trie_get(vt: *mut VerkleTrie, key: *const u8) -> *const u8 {
    let _vt = unsafe{&mut *vt};
    match _vt {
        VerkleTrie::MemoryTest(vt) => vt.verkle_trie_get(key),
        VerkleTrie::MemoryPrelagrange(vt) => vt.verkle_trie_get(key),
        VerkleTrie::RocksdbTest(vt) => vt.verkle_trie_get(key),
    }
}

#[no_mangle]
pub extern fn verkle_trie_insert(vt: *mut VerkleTrie, key: *const u8, value: *const u8) {
    let _vt = unsafe{&mut *vt};
    match _vt {
        VerkleTrie::MemoryTest(vt) => vt.verkle_trie_insert(key, value),
        VerkleTrie::MemoryPrelagrange(vt) => vt.verkle_trie_insert(key, value),
        VerkleTrie::RocksdbTest(vt) => vt.verkle_trie_insert(key, value),
    }
}

#[no_mangle]
pub extern fn get_root_hash(vt: *mut VerkleTrie) -> *const u8 {
    let _vt = unsafe{&mut *vt};
    match _vt {
        VerkleTrie::MemoryTest(vt) => vt.get_root_hash(),
        VerkleTrie::MemoryPrelagrange(vt) => vt.get_root_hash(),
        VerkleTrie::RocksdbTest(vt) => vt.get_root_hash(),
    }
}

#[no_mangle]
pub extern fn get_verkle_proof(vt: *mut VerkleTrie, key: *const u8) -> *mut Proof {
    let _vt = unsafe{&mut *vt};
    match _vt {
        VerkleTrie::MemoryTest(vt) => vt.get_verkle_proof(key),
        VerkleTrie::MemoryPrelagrange(vt) => vt.get_verkle_proof(key),
        VerkleTrie::RocksdbTest(vt) => vt.get_verkle_proof(key),
    }
}

#[no_mangle]
pub extern fn verify_verkle_proof(vt: *mut VerkleTrie, ptr: *const u8, proof_len: usize, key: *const u8, value: *const u8) -> u8 {
    let _vt = unsafe{&mut *vt};
    match _vt {
        VerkleTrie::MemoryTest(vt) => vt.verify_verkle_proof(ptr, proof_len, key, value),
        VerkleTrie::MemoryPrelagrange(vt) => vt.verify_verkle_proof(ptr, proof_len, key, value),
        VerkleTrie::RocksdbTest(vt) => vt.verify_verkle_proof(ptr, proof_len, key, value),
    }
}

#[no_mangle]
pub extern fn get_verkle_proof_multiple(vt: *mut VerkleTrie, keys: *const [u8;32], len: usize) -> *mut Proof{
    let _vt = unsafe{&mut *vt};
    match _vt {
        VerkleTrie::MemoryTest(vt) => vt.get_verkle_proof_multiple(keys, len),
        VerkleTrie::MemoryPrelagrange(vt) => vt.get_verkle_proof_multiple(keys, len),
        VerkleTrie::RocksdbTest(vt) => vt.get_verkle_proof_multiple(keys, len),
    }
}

#[no_mangle]
pub extern fn verify_verkle_proof_multiple(vt: *mut VerkleTrie, ptr: *const u8, proof_len: usize, keys: *const [u8;32], vals: *const [u8;32], len: usize) -> u8 {
    let _vt = unsafe{&mut *vt};
    match _vt {
        VerkleTrie::MemoryTest(vt) => vt.verify_verkle_proof_multiple(ptr, proof_len, keys, vals, len),
        VerkleTrie::MemoryPrelagrange(vt) => vt.verify_verkle_proof_multiple(ptr, proof_len, keys, vals, len),
        VerkleTrie::RocksdbTest(vt) => vt.verify_verkle_proof_multiple(ptr, proof_len, keys, vals, len),
    }
}

#[no_mangle]
pub extern fn verkle_trie_insert_multiple(vt: *mut VerkleTrie, keys: *const [u8;32], vals: *const [u8;32], len: usize){
    let _vt = unsafe{&mut *vt};
    match _vt {
        VerkleTrie::MemoryTest(vt) => vt.verkle_trie_insert_multiple(keys, vals, len),
        VerkleTrie::MemoryPrelagrange(vt) => vt.verkle_trie_insert_multiple(keys, vals, len),
        VerkleTrie::RocksdbTest(vt) => vt.verkle_trie_insert_multiple(keys, vals, len),
    }
}

pub fn get_array_from_slice_argument(sl: *const u8) -> [u8; 32] {
    let _raw_slice = unsafe {
        assert!(!sl.is_null());
        slice::from_raw_parts(sl, 32)
    };
    _raw_slice.try_into().expect("slice with incorrect length")
}

pub fn get_vector_from_slice_argument(ptr: *const [u8;32], len: usize) -> Vec<[u8;32]>{
    assert!(!ptr.is_null());
    let _raw_slice = unsafe { slice::from_raw_parts(ptr, len)};
    let mut raw_slice = vec![_raw_slice[0]];
    for i in 1..= len - 1{
        raw_slice.push(_raw_slice[i]);
    }
    raw_slice
}

pub fn proof_ptr_to_proof_vec(ptr: *const u8, len:usize) -> Vec<u8>{
    assert!(!ptr.is_null());
    let _raw_slice = unsafe { slice::from_raw_parts(ptr, len)};
    // println!("{:?}",_raw_slice);
    let mut raw_slice = vec![_raw_slice[0]];
    for i in 1..= len - 1{
        raw_slice.push(_raw_slice[i]);
    }
    raw_slice
}

#[cfg(test)]
mod tests {
    use crate::{get_verkle_proof, verkle_trie_new, verify_verkle_proof, get_root_hash};
    use crate::verkle_trie_insert;
    use crate::verkle_trie_get;
    use crate::verkle_trie_insert_multiple;
    use crate::get_verkle_proof_multiple;
    use crate::verify_verkle_proof_multiple;
    use crate::get_array_from_slice_argument;
    use std::mem::transmute;

    #[test]
    fn root_hash() {
        let trie = verkle_trie_new(0,0);
        let hash_ptr = get_root_hash(trie);
        let hash = get_array_from_slice_argument(hash_ptr);
        assert_eq!(hash, [0u8; 32]);
    }

    #[test]
    fn insert_fetch() {
        let trie = verkle_trie_new(0,0);

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
        let trie = verkle_trie_new(0,0);

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

    #[test]
    fn gen_verify_proof() {
        let trie = verkle_trie_new(0,0);

        let _one:[u8;32] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ];
        let one: *const u8  = unsafe {transmute(Box::new(_one))};
        let _one_32:[u8;32] = [1; 32];
        let one_32 = unsafe {transmute(Box::new(_one_32))};
        verkle_trie_insert(trie, one, one);
        verkle_trie_insert(trie, one_32, one);
        let _proof = get_verkle_proof(trie, one);
        let proof = unsafe{&mut *_proof};
        let verif = verify_verkle_proof(trie, proof.ptr, proof.len, one, one);
        assert_eq!(verif, 1);
        let verif = verify_verkle_proof(trie, proof.ptr, proof.len, one, one_32);
        assert_eq!(verif, 0);
    }

    #[test]
    fn generate_proof_test(){
        let trie = verkle_trie_new(0,0);

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

        verkle_trie_insert_multiple(trie, all_keys.as_ptr(), all_vals.as_ptr(), all_keys.len());

        let mut _proof = get_verkle_proof_multiple(trie, all_keys.as_ptr(), all_keys.len());
        let proof = unsafe{&mut *_proof};
        let verification = verify_verkle_proof_multiple(trie, proof.ptr, proof.len, all_keys.as_ptr(), all_vals.as_ptr(), all_keys.len());
        assert_eq!(verification, 1);
    }
}

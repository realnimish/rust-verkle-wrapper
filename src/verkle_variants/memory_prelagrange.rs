use std::ptr;
use std::mem::transmute;
use verkle_trie::{database::{memory_db::MemoryDb}, trie::Trie};
use verkle_trie::committer::precompute::PrecomputeLagrange;
use verkle_trie::config::{VerkleConfig};
use verkle_trie::TrieTrait;
use verkle_trie::proof::VerkleProof;
use verkle_trie::to_bytes::ToBytes;

use crate::{
    Proof,
    get_array_from_slice_argument,
    get_vector_from_slice_argument,
    proof_ptr_to_proof_vec,
};

pub struct VerkleTrie {
    trie: Trie<MemoryDb, PrecomputeLagrange>,
}

pub fn verkle_trie_new() -> VerkleTrie {
    let _db = MemoryDb::new();
    let config = VerkleConfig::new(_db);
    let mut _trie = Trie::new(config);
    let vt = VerkleTrie{ trie: _trie };
    vt
}

pub fn verkle_trie_get(vt: &mut VerkleTrie, key: *const u8) -> *const u8 {
    let _key = get_array_from_slice_argument(key);
    let _result = &vt.trie.get(_key);
    match _result {
        Some(x) => {
            let _result = unsafe { transmute ( Box::new(*x))};
            _result
        }
        None  => ptr::null(),
    }
}

pub fn verkle_trie_insert(vt: &mut VerkleTrie, key: *const u8, value: *const u8) {
    let _key = get_array_from_slice_argument(key);
    let _value = get_array_from_slice_argument(value);
    vt.trie.insert_single(_key,_value);
}

pub fn get_root_hash(vt: &mut VerkleTrie) -> *const u8 {
    let hash = vt.trie.root_hash();
    let (hash_ptr, _, _) = hash.to_bytes().into_raw_parts();
    hash_ptr
}

pub fn get_verkle_proof(vt: &mut VerkleTrie, key: *const u8) -> *mut Proof {
    let _key = get_array_from_slice_argument(key);
    let _proof = vt.trie.create_verkle_proof(vec![_key].into_iter());
    let mut proof_bytes = Vec::new();
    _proof.write(&mut proof_bytes);
    let(_ptr, _len, _) = proof_bytes.into_raw_parts();
    let proof = Proof{ ptr: _ptr, len: _len};
    unsafe{ transmute( Box::new(proof))}
}

pub fn verify_verkle_proof(vt: &mut VerkleTrie, ptr: *const u8, proof_len: usize, key: *const u8, value: *const u8) -> u8 {
    let proof_bytes = proof_ptr_to_proof_vec(ptr, proof_len);
    let proof = VerkleProof::read(&proof_bytes[..]).unwrap();
    let _key = get_array_from_slice_argument(key);
    let _value = get_array_from_slice_argument(value);
    let root = vt.trie.root_commitment();
    let val_iter = vec![Some(_value)];
    let vpp = proof.clone();
    let (res, _) = vpp.check( vec![_key], val_iter, root);
    let result = res as u8;
    result
}

pub fn get_verkle_proof_multiple(vt: &mut VerkleTrie, keys: *const [u8;32], len: usize) -> *mut Proof{
    let _keys = get_vector_from_slice_argument(keys, len);
    let _proof = vt.trie.create_verkle_proof(_keys.into_iter());
    let mut proof_bytes = Vec::new();
    _proof.write(&mut proof_bytes);
    let(_ptr, _len, _) = proof_bytes.into_raw_parts();
    let proof = Proof{ ptr: _ptr, len: _len};
    unsafe{ transmute( Box::new(proof))}
}

pub fn verify_verkle_proof_multiple(vt: &mut VerkleTrie, ptr: *const u8, proof_len: usize, keys: *const [u8;32], vals: *const [u8;32], len: usize) -> u8 {
    let proof_bytes = proof_ptr_to_proof_vec(ptr, proof_len);
    let proof = VerkleProof::read(&proof_bytes[..]).unwrap();
    let _keys = get_vector_from_slice_argument(keys, len);
    let _vals = get_vector_from_slice_argument(vals, len);
    let root = vt.trie.root_commitment();
    let values: Vec<_> = _vals.iter().map(|val| Some(*val)).collect();
    let vpp = proof.clone();
    let (res, _) = vpp.check(_keys, values, root);
    let result = res as u8;
    result
}

pub fn verkle_trie_insert_multiple(vt: &mut VerkleTrie, keys: *const [u8;32], vals: *const [u8;32], len: usize){
    let _keys = get_vector_from_slice_argument(keys, len);
    let _vals = get_vector_from_slice_argument(vals, len);
    let mut itr = vec![(_keys[0], _vals[0])];
    for i in 1..=_keys.len() - 1{
        itr.push((_keys[i], _vals[i]));
    }
    vt.trie.insert(itr.into_iter());
}
use std::mem::transmute;
use rust_verkle::*;

fn main() {
    let database_scheme = 0;
    let commit_scheme = 1;

    println!("creating new trie...");
    let trie = verkle_trie_new(database_scheme, commit_scheme);

    let _one:[u8;32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 1,
    ];
    let one: *const u8  = unsafe {transmute(Box::new(_one))};
    let _one_32:[u8;32] = [1; 32];
    let one_32: *const u8 = unsafe {transmute(Box::new(_one_32))};

    println!("inserting first set of values...");
    verkle_trie_insert(trie, one, one);

    println!("inserting second set of values...");
    verkle_trie_insert(trie, one_32, one);

    println!("fetching values..");
    let val = verkle_trie_get(trie, one_32);
    let _val: Box<[u8;32]> = unsafe { transmute(val)};
    let result = * _val;
    assert_eq!(result, _one);

    println!("creating proof...");
    let mut _proof = get_verkle_proof(trie, one_32);
    let proof = unsafe{&mut *_proof};

    println!("verifying proofs...");
    let mut check = verify_verkle_proof(trie, proof.ptr, proof.len, one_32, one);
    assert_eq!(check, 1);

    println!("Creating another trie");
    let trie2 = verkle_trie_new(database_scheme, commit_scheme);

    let keys = vec![_one,_one_32];
    let vals = vec![_one_32,_one];
    let len = keys.len();
    let key_ptr = keys.as_ptr();
    let val_ptr = vals.as_ptr();

    println!("Inserting multiple values");
    verkle_trie_insert_multiple(trie2, key_ptr, val_ptr, len);

    println!("Checking for inserted values");
    let val2 = verkle_trie_get(trie2, one);
    let _val2: Box<[u8;32]> = unsafe { transmute(val2)};
    let result2 = * _val2;
    assert_eq!(result2, _one_32);

    println!("Creating proof for multiple Key Vals");
    let mut _proof2 = get_verkle_proof_multiple(trie2, key_ptr, len);
    let proof2 = unsafe{ &mut *_proof2};

    // println!("verifying proof 1");
    // check = verify_verkle_proof(trie2, proof2, one_32, one);
    // assert!(check);

    // println!("verifying proofs 2");
    // check = verify_verkle_proof(trie2, proof2, one_32, one);
    // assert!(check);

    println!("verifying multiple proofs");
    check = verify_verkle_proof_multiple(trie2, proof2.ptr, proof2.len, key_ptr, val_ptr, len);
    assert_eq!(check, 1);

    println!("All Correct");
}
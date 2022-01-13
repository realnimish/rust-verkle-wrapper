// use rust_verkle::{dummy_setup, verkle_trie_new, verkle_trie_insert, verkle_trie_create_path, verkle_trie_create_proof, verkle_trie_verify};
use rust_verkle::verkle_trie_new;
use rust_verkle::verkle_trie_insert;
use rust_verkle::verkle_trie_get;
use rust_verkle::get_array_from_slice_argument;
use std::mem::transmute;

fn main() {

    println!("creating new trie...");
    let trie = verkle_trie_new();

    let _one:[u8;32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 1,
    ];
    let one: *const u8  = unsafe {transmute(Box::new(_one))};
    let _one_32:[u8;32] = [1; 32];
    let one_32 = unsafe {transmute(Box::new(_one_32))};

    println!("inserting first set of values...");
    verkle_trie_insert(trie, one, one);

    println!("inserting second set of values...");
    verkle_trie_insert(trie, one_32, one);

    println!("fetching values..");
    let val = verkle_trie_get(trie, one_32);
    let _val: Box<[u8;32]> = unsafe { transmute(val)};
    let result = * _val;
    assert_eq!(result, _one);

}
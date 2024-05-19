use bincode;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fs::File;
use std::io::{Read, Write};

pub fn dump_to_file<T: Serialize>(key: &T, filename: &str) {
    let encoded: Vec<u8> = bincode::serialize(key).unwrap();
    let mut file = File::create(filename).unwrap();
    file.write_all(&encoded).unwrap();
}

pub fn read_from_file<T: DeserializeOwned>(filename: &str) -> T {
    let mut file = File::open(filename).unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();
    bincode::deserialize(&buffer).unwrap()
}

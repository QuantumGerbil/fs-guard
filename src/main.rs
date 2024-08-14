mod sha256;
mod merkle;

use crate::sha256::bytes_to_hex;
struct Sha256Hasher;
use std::env;
use std::fs;
use std::io::{self, Read};

impl crate::merkle::HashFunction for Sha256Hasher {
    fn hash(&self, input: &[u8]) -> Vec<u8> {
        crate::sha256::sha256(input).to_vec()
    }
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <file_or_directory>", args[0]);
        return Ok(());
    }

    let path = &args[1];
    let metadata = fs::metadata(path)?;

    let mut data_blocks = Vec::new();

    if metadata.is_file() {
        // Read the file content
        let mut file = fs::File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        data_blocks.push(buffer);
    } else if metadata.is_dir() {
        // Read each file in the directory
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let mut file = fs::File::open(path)?;
                let mut buffer = Vec::new();
                file.read_to_end(&mut buffer)?;
                data_blocks.push(buffer);
            }
        }
    } else {
        eprintln!("Invalid path: {}", path);
        return Ok(());
    }

    // Create a new Merkle Tree with the SHA-256 hasher
    let mut merkle_tree = crate::merkle::MerkleTree::new(Sha256Hasher);

    // Convert data_blocks to slices
    let data_slices: Vec<&[u8]> = data_blocks.iter().map(|block| block.as_slice()).collect();

    // Build the Merkle Tree
    merkle_tree.build(data_slices);

    // Get the Merkle root
    if let Some(root_hash) = merkle_tree.root_hash() {
        println!("Merkle Root: {:?}", bytes_to_hex(root_hash));
    } else {
        println!("Merkle Tree is empty.");
    }

    Ok(())
}
mod sha256;
mod merkle;

fn main() {
    let data = "hello world";
    let hash = sha256::sha256(data.as_bytes());
    // Convert the byte array to a hexadecimal string
    let hex_output = bytes_to_hex(&hash);

    println!("SHA-256 Hex: {}", hex_output);
    println!("SHA-256: {:?}", hash);
    
    // Create a new Merkle Tree with the SHA-256 hasher
    let mut merkle_tree = merkle::MerkleTree::new(Sha256Hasher);

    // Data blocks to be included in the Merkle Tree
    let data_blocks: Vec<&[u8]> = vec![b"block1", b"block2", b"block3", b"block4"];

    // Build the Merkle Tree
    merkle_tree.build(data_blocks);

    // Get the Merkle root
    if let Some(root_hash) = merkle_tree.root_hash() {
        println!("Merkle Root: {:?}", bytes_to_hex(root_hash));

        // Generate a proof for the first leaf
        if let Some(proof) = merkle_tree.generate_proof(0) {
            println!("Proof for first leaf: {:?}", proof.iter().map(|h| bytes_to_hex(h)).collect::<Vec<_>>());

            // Verify the proof
            let is_valid = merkle_tree.verify_proof(b"block1", proof, root_hash);
            println!("Proof is valid: {}", is_valid);
        }
    } else {
        println!("Merkle Tree is empty.");
    }
}

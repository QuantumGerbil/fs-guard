mod sha256;
mod merkle;
mod utility;

use crate::utility::bytes_to_hex;
struct Sha256Hasher;

impl crate::merkle::HashFunction for Sha256Hasher {
    fn hash(&self, input: &[u8]) -> Vec<u8> {
        crate::sha256::sha256(input).to_vec()
    }
}

/*fn main() -> io::Result<()> {
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
}*/

fn main() {
    // Create a new Merkle Tree with the SHA-256 hasher
    let mut merkle_tree = merkle::MerkleTree::new(Sha256Hasher);

    // Data blocks to be included in the Merkle Tree
    let data_blocks: Vec<&[u8]> = vec![b"block1", b"block2", b"block3", b"block4"];

    // Build the Merkle Tree
    merkle_tree.build(data_blocks);

    // Get the Merkle root
    if let Some(root_hash) = merkle_tree.root_hash() {
        #[cfg(debug_assertions)]
        println!("Merkle Root: {:?}", bytes_to_hex(root_hash));

        // Generate a proof for the first leaf
        if let Some(proof) = merkle_tree.generate_proof(0) {
            println!("Proof for first leaf: {:?}", proof.iter().map(|h| bytes_to_hex(h)).collect::<Vec<_>>());

            // Verify the proof
            let is_valid = merkle_tree.verify_proof(b"block1", proof, root_hash);
            println!("Proof is valid: {}", is_valid);
        }
        
        // Generate a proof for the second leaf
        if let Some(proof) = merkle_tree.generate_proof(1) {
            println!("Proof for second leaf: {:?}", proof.iter().map(|h| bytes_to_hex(h)).collect::<Vec<_>>());

            // Verify the proof
            let is_valid = merkle_tree.verify_proof(b"block2", proof, root_hash);
            println!("Proof is valid: {}", is_valid);
        }
        
        // Generate a proof for the third leaf
        if let Some(proof) = merkle_tree.generate_proof(2) {
            println!("Proof for third leaf: {:?}", proof.iter().map(|h| bytes_to_hex(h)).collect::<Vec<_>>());

            // Verify the proof
            let is_valid = merkle_tree.verify_proof(b"block3", proof, root_hash);
            println!("Proof is valid: {}", is_valid);
        }
        
        // Generate a proof for the first leaf
        if let Some(proof) = merkle_tree.generate_proof(3) {
            println!("Proof for fourth leaf: {:?}", proof.iter().map(|h| bytes_to_hex(h)).collect::<Vec<_>>());

            // Verify the proof
            let is_valid = merkle_tree.verify_proof(b"block4", proof, root_hash);
            println!("Proof is valid: {}", is_valid);
        }
    } else {
        println!("Merkle Tree is empty.");
    }
}

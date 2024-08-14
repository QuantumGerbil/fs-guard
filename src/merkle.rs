use std::fmt::Debug;
#[cfg(debug_assertions)]
use crate::utility;

/// Trait for hashing functions
pub trait HashFunction {
    fn hash(&self, input: &[u8]) -> Vec<u8>;
}

/// Merkle Tree Node
#[derive(Debug, Clone)]
pub struct MerkleNode {
    hash: Vec<u8>,
    #[allow(dead_code)]
    left: Option<Box<MerkleNode>>,
    #[allow(dead_code)]
    right: Option<Box<MerkleNode>>,
}

/// Merkle Tree
pub struct MerkleTree<H: HashFunction> {
    root: Option<MerkleNode>,
    hasher: H,
    leaves: Vec<MerkleNode>,
}

impl<H: HashFunction> MerkleTree<H> {
    /// Create a new Merkle Tree with the given hasher
    pub fn new(hasher: H) -> Self {
        MerkleTree { root: None, hasher, leaves: Vec::new() }
    }

    /// Build the Merkle Tree from a list of data blocks
    pub fn build(&mut self, data_blocks: Vec<&[u8]>) {
        self.leaves = data_blocks
            .into_iter()
            .map(|data| MerkleNode {
                hash: self.hasher.hash(data),
                left: None,
                right: None,
            })
            .collect();

        let mut nodes = self.leaves.clone();

        while nodes.len() > 1 {
            let mut next_level = Vec::new();

            for i in (0..nodes.len()).step_by(2) {
                let left = Box::new(nodes[i].clone());
                let right = if i + 1 < nodes.len() {
                    Box::new(nodes[i + 1].clone())
                } else {
                    Box::new(nodes[i].clone()) // Duplicate last node if odd number
                };
                
                let combined_hash = if left.hash.clone() < right.hash.clone() {
                    [left.hash.clone(), right.hash.clone()].concat()
                } else {
                    [right.hash.clone(), left.hash.clone()].concat()
                };
                //let combined_hash = [left.hash.clone(), right.hash.clone()].concat();
                let parent_hash = self.hasher.hash(&combined_hash);

                next_level.push(MerkleNode {
                    hash: parent_hash,
                    left: Some(left),
                    right: Some(right),
                });
            }

            nodes = next_level;
        }

        self.root = nodes.into_iter().next();
    }

    /// Get the Merkle root of the tree
    pub fn root_hash(&self) -> Option<&[u8]> {
        self.root.as_ref().map(|node| node.hash.as_slice())
    }
    
    /// Generate a proof for a given leaf index
    pub fn generate_proof(&self, index: usize) -> Option<Vec<Vec<u8>>> {
        if index >= self.leaves.len() {
            return None;
        }

        let mut proof = Vec::new();
        let mut current_index = index;
        let mut nodes = self.leaves.clone();
        
        // Print initial leaf hashes
        #[cfg(debug_assertions)]
        {
            println!("Leaf hashes:");
            for node in &nodes {
                println!("{:?}", utility::bytes_to_hex(&node.hash));
            }
        }

        while nodes.len() > 1 {
            let mut next_level = Vec::new();

            for i in (0..nodes.len()).step_by(2) {
                let left = &nodes[i];
                let right = if i + 1 < nodes.len() {
                    &nodes[i + 1]
                } else {
                    left
                };
                
                // Print the hashes being combined
                #[cfg(debug_assertions)]
                println!("Combining hashes: {:?} and {:?}", utility::bytes_to_hex(&left.hash), utility::bytes_to_hex(&right.hash));

                if i == current_index || i + 1 == current_index {
                    if i == current_index {
                        proof.push(right.hash.clone());
                        #[cfg(debug_assertions)]
                        println!("Adding to proof: {:?}", utility::bytes_to_hex(&right.hash));
                    } else {
                        proof.push(left.hash.clone());
                        #[cfg(debug_assertions)]
                        println!("Adding to proof: {:?}", utility::bytes_to_hex(&left.hash));
                    }
                    current_index /= 2;
                }

                let combined_hash = if left.hash.clone() < right.hash.clone() {
                    [left.hash.clone(), right.hash.clone()].concat()
                } else {
                    [right.hash.clone(), left.hash.clone()].concat()
                };
                //let combined_hash = [left.hash.clone(), right.hash.clone()].concat();
                let parent_hash = self.hasher.hash(&combined_hash);
                
                // Print the parent hash
                #[cfg(debug_assertions)]
                println!("Parent hash: {:?}", utility::bytes_to_hex(&parent_hash));

                next_level.push(MerkleNode {
                    hash: parent_hash,
                    left: None,
                    right: None,
                });
            }

            nodes = next_level;
        }

        Some(proof)
    }

    /// Verify a proof for a given leaf and expected root
    pub fn verify_proof(&self, leaf: &[u8], proof: Vec<Vec<u8>>, expected_root: &[u8]) -> bool {
        let mut hash = self.hasher.hash(leaf);
        #[cfg(debug_assertions)]
        println!("Initial leaf hash: {:?}", utility::bytes_to_hex(&hash));

        #[cfg(debug_assertions)]
        {
        for (i, sibling_hash) in proof.iter().enumerate() {
        println!("Sibling hash {}: {:?}", i, utility::bytes_to_hex(sibling_hash));
        
            let combined_hash = if hash < *sibling_hash {
                [hash.clone(), sibling_hash.clone()].concat()
            } else {
                [sibling_hash.clone(), hash.clone()].concat()
            };
            //let combined_hash = [hash.clone(), sibling_hash.clone()].concat()
            hash = self.hasher.hash(&combined_hash);
            println!("Combined hash {}: {:?}", i, utility::bytes_to_hex(&hash));
        }
        }
        
        #[cfg(not(debug_assertions))]
        {
        for sibling_hash in proof.iter() {

            let combined_hash = if hash < *sibling_hash {
                [hash.clone(), sibling_hash.clone()].concat()
            } else {
                [sibling_hash.clone(), hash.clone()].concat()
            };
            //let combined_hash = [hash.clone(), sibling_hash.clone()].concat()
            hash = self.hasher.hash(&combined_hash);
        }
        }
        
        #[cfg(debug_assertions)]
        {
            println!("Final computed hash: {:?}", utility::bytes_to_hex(&hash));
            println!("Expected root hash: {:?}", utility::bytes_to_hex(expected_root));
        }

        hash == expected_root
    }
}

#[cfg(test)]
mod tests {
    use crate::sha256::sha256;
    use crate::merkle::MerkleTree;
    use crate::Sha256Hasher;
    use crate::sha256;
    
        #[test]
    fn test_merkle_tree_single_block() {
        let hasher = Sha256Hasher;
        let mut merkle_tree = MerkleTree::new(hasher);

        // Single data block
        let data_blocks: Vec<&[u8]> = vec![b"block1"];
        merkle_tree.build(data_blocks);

        // Expected hash for a single block (replace with actual expected hash)
        let expected_root = sha256(b"block1").to_vec();
        let root_hash = merkle_tree.root_hash().unwrap();

        assert_eq!(root_hash, expected_root);
    }

    #[test]
    fn test_merkle_tree_multiple_blocks() {
        let hasher = Sha256Hasher;
        let mut merkle_tree = MerkleTree::new(hasher);

        // Multiple data blocks
        let data_blocks: Vec<&[u8]> = vec![b"block1", b"block2", b"block3", b"block4"];
        merkle_tree.build(data_blocks);

        // Manually calculate the expected Merkle root
        let hash1 = sha256::sha256(b"block1");
        let hash2 = sha256::sha256(b"block2");
        let hash3 = sha256::sha256(b"block3");
        let hash4 = sha256::sha256(b"block4");

        let combined1 = [hash1.to_vec(), hash2.to_vec()].concat();
        let combined2 = [hash3.to_vec(), hash4.to_vec()].concat();

        let parent1 = sha256::sha256(&combined1);
        let parent2 = sha256::sha256(&combined2);

        let combined_root = [parent1.to_vec(), parent2.to_vec()].concat();
        let expected_root = sha256::sha256(&combined_root).to_vec();

        let root_hash = merkle_tree.root_hash().unwrap();

        assert_eq!(root_hash, expected_root);
    }

    #[test]
    fn test_merkle_tree_empty() {
        let hasher = Sha256Hasher;
        let mut merkle_tree = MerkleTree::new(hasher);

        // No data blocks
        let data_blocks: Vec<&[u8]> = vec![];
        merkle_tree.build(data_blocks);

        // Expected root should be None
        assert!(merkle_tree.root_hash().is_none());
    }
}

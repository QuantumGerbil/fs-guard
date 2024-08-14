use std::fmt::Debug;

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
}

impl<H: HashFunction> MerkleTree<H> {
    /// Create a new Merkle Tree with the given hasher
    pub fn new(hasher: H) -> Self {
        MerkleTree { root: None, hasher }
    }

    /// Build the Merkle Tree from a list of data blocks
    pub fn build(&mut self, data_blocks: Vec<&[u8]>) {
        let mut nodes: Vec<MerkleNode> = data_blocks
            .into_iter()
            .map(|data| MerkleNode {
                hash: self.hasher.hash(data),
                left: None,
                right: None,
            })
            .collect();

        while nodes.len() > 1 {
            let mut next_level = Vec::new();

            for i in (0..nodes.len()).step_by(2) {
                let left = Box::new(nodes[i].clone());
                let right = if i + 1 < nodes.len() {
                    Box::new(nodes[i + 1].clone())
                } else {
                    Box::new(nodes[i].clone()) // Duplicate last node if odd number
                };

                let combined_hash = [left.hash.clone(), right.hash.clone()].concat();
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256::sha256;
    use crate::merkle::MerkleTree;
    
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

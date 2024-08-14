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

    /// Generate a Merkle proof for the leaf at the given index.
    pub fn generate_proof(&self, index: usize) -> Option<Vec<Vec<u8>>> {
        let mut proof = Vec::new();
        let mut current_index = index;
        let mut current_level = self.leaves();

        while current_level.len() > 1 {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            if sibling_index < current_level.len() {
                proof.push(current_level[sibling_index].hash.clone());
            }

            current_index /= 2;
            current_level = self.next_level(&current_level);
        }

        Some(proof)
    }

    /// Verify a Merkle proof for a given leaf and root hash.
    pub fn verify_proof(&self, leaf: &[u8], proof: Vec<Vec<u8>>, root_hash: &[u8]) -> bool {
        let mut current_hash = self.hasher.hash(leaf);

        for sibling_hash in proof {
            let combined_hash = if current_hash < sibling_hash {
                [current_hash, sibling_hash].concat()
            } else {
                [sibling_hash, current_hash].concat()
            };
            current_hash = self.hasher.hash(&combined_hash);
        }

        current_hash == root_hash
    }

    /// Retrieve the leaf nodes of the Merkle tree.
    fn leaves(&self) -> Vec<MerkleNode> {
        let mut leaves = Vec::new();
        if let Some(root) = &self.root {
            self.collect_leaves(root, &mut leaves);
        }
        leaves
    }

    /// Helper method to recursively collect leaves from the tree.
    fn collect_leaves(&self, node: &MerkleNode, leaves: &mut Vec<MerkleNode>) {
        if node.left.is_none() && node.right.is_none() {
            leaves.push(node.clone());
        } else {
            if let Some(left) = &node.left {
                self.collect_leaves(left, leaves);
            }
            if let Some(right) = &node.right {
                self.collect_leaves(right, leaves);
            }
        }
    }

    /// Compute the next level of nodes from the current level.
    fn next_level(&self, current_level: &[MerkleNode]) -> Vec<MerkleNode> {
        let mut next_level = Vec::new();
        for i in (0..current_level.len()).step_by(2) {
            let left = &current_level[i];
            let right = if i + 1 < current_level.len() {
                &current_level[i + 1]
            } else {
                left // Duplicate last node if odd number
            };

            let combined_hash = [left.hash.clone(), right.hash.clone()].concat();
            let parent_hash = self.hasher.hash(&combined_hash);

            next_level.push(MerkleNode {
                hash: parent_hash,
                left: Some(Box::new(left.clone())),
                right: Some(Box::new(right.clone())),
            });
        }
        next_level
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

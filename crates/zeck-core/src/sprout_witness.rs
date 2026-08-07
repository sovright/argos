//! Sprout incremental Merkle tree, and the witness format the prover wants.
//!
//! `zcash_proofs::sprout::create_proof` takes each input's authentication
//! path as `[u8; WITNESS_PATH_SIZE]` — 966 bytes laid out as a depth byte,
//! 29 length-prefixed siblings ordered root-first, then an 8-byte
//! little-endian position. zcashd produces those bytes by serializing
//! `IncrementalWitness::path()`.
//!
//! `argos-wallet-import` preserves each cached witness verbatim and
//! deliberately never decodes it. This module is where it gets decoded, which
//! means reimplementing enough of `zcash/src/zcash/IncrementalMerkleTree.cpp`
//! to walk one: the tree itself, the empty-root table, the path filler, and
//! the witness's cursor.
//!
//! # Why not rebuild the tree from the chain instead
//!
//! Because it cannot be done from a lightwalletd. Compact blocks carry
//! Sapling and Orchard commitments only — no JoinSplit data — so
//! reconstructing a Sprout note's path would need every full block from
//! genesis to the anchor, i.e. a trusted full node. The witness zcashd
//! already cached in the wallet is the only path available to a
//! lightwalletd-backed recovery tool.
//!
//! The anchor that witness carries may be years old. That is fine for
//! consensus — any historical root is a valid anchor — and is exactly why
//! preserving the witness was worth doing.
//!
//! # Testing
//!
//! No fixture holds a funded Sprout note (zcashd refuses inbound Sprout
//! transfers regardless of Canopy height), so there is no real witness blob
//! to decode. What is checkable without one is the invariant that matters:
//! a path is only useful if it reproduces the tree's root. The tests build
//! trees, take witnesses, and verify that folding each path back up yields
//! the same root the tree reports — which is what the circuit will check.

use crate::sprout::sha256_compress;

/// Sprout's note commitment tree depth (`INCREMENTAL_MERKLE_TREE_DEPTH`).
pub const TREE_DEPTH: usize = 29;

/// The serialized authentication path `create_proof` expects:
/// depth byte + 29 × (length byte + 32-byte sibling) + 8-byte position.
pub const WITNESS_PATH_SIZE: usize = 1 + 33 * TREE_DEPTH + 8;

type Node = [u8; 32];

/// `HashCombine` for Sprout: the bare SHA-256 compression function over the
/// concatenation. The depth argument the C++ signature carries is unused for
/// Sprout, so it is omitted here rather than threaded through and ignored.
fn combine(left: &Node, right: &Node) -> Node {
    let mut block = [0u8; 64];
    block[..32].copy_from_slice(left);
    block[32..].copy_from_slice(right);
    sha256_compress(&block)
}

/// `empty_roots[d]` is the root of an all-empty subtree of depth `d`.
///
/// Sprout's uncommitted leaf is 32 zero bytes, unlike Sapling's, where it is
/// a specific field element.
fn empty_roots() -> [Node; TREE_DEPTH + 1] {
    let mut roots = [[0u8; 32]; TREE_DEPTH + 1];
    for d in 1..=TREE_DEPTH {
        roots[d] = combine(&roots[d - 1], &roots[d - 1]);
    }
    roots
}

/// Supplies the "uncle" hashes a partial tree is missing, falling back to
/// empty roots once the witness's own cached uncles run out.
struct PathFiller {
    queue: std::collections::VecDeque<Node>,
    empty: [Node; TREE_DEPTH + 1],
}

impl PathFiller {
    fn new(uncles: Vec<Node>) -> Self {
        Self {
            queue: uncles.into(),
            empty: empty_roots(),
        }
    }

    fn next(&mut self, depth: usize) -> Node {
        self.queue.pop_front().unwrap_or(self.empty[depth])
    }
}

/// A Sprout incremental Merkle tree, mirroring zcashd's
/// `IncrementalMerkleTree<29, SHA256Compress>`.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct IncrementalMerkleTree {
    left: Option<Node>,
    right: Option<Node>,
    /// `parents[i]` is the pending left sibling at depth `i + 1`.
    parents: Vec<Option<Node>>,
}

impl IncrementalMerkleTree {
    pub fn append(&mut self, obj: Node) -> Result<(), WitnessError> {
        if self.is_complete(TREE_DEPTH) {
            return Err(WitnessError::TreeFull);
        }
        if self.left.is_none() {
            self.left = Some(obj);
        } else if self.right.is_none() {
            self.right = Some(obj);
        } else {
            let mut combined = combine(
                &self.left.expect("left is set"),
                &self.right.expect("right is set"),
            );
            self.left = Some(obj);
            self.right = None;
            for i in 0..TREE_DEPTH {
                if i < self.parents.len() {
                    if let Some(parent) = self.parents[i] {
                        combined = combine(&parent, &combined);
                        self.parents[i] = None;
                    } else {
                        self.parents[i] = Some(combined);
                        return Ok(());
                    }
                } else {
                    self.parents.push(Some(combined));
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    fn is_complete(&self, depth: usize) -> bool {
        self.left.is_some()
            && self.right.is_some()
            && self.parents.len() == depth.saturating_sub(1)
            && self.parents.iter().all(Option::is_some)
    }

    /// The depth at which the next witness cursor should sit, skipping
    /// `skip` already-filled uncles.
    fn next_depth(&self, mut skip: usize) -> usize {
        if self.left.is_none() {
            if skip == 0 {
                return 0;
            }
            skip -= 1;
        }
        if self.right.is_none() {
            if skip == 0 {
                return 0;
            }
            skip -= 1;
        }
        let mut d = 1;
        for parent in &self.parents {
            if parent.is_none() {
                if skip == 0 {
                    return d;
                }
                skip -= 1;
            }
            d += 1;
        }
        d + skip
    }

    fn root_with(&self, depth: usize, filler: &mut PathFiller) -> Node {
        let combine_left = self.left.unwrap_or_else(|| filler.next(0));
        let combine_right = self.right.unwrap_or_else(|| filler.next(0));
        let mut root = combine(&combine_left, &combine_right);

        let mut d = 1;
        for parent in &self.parents {
            root = match parent {
                Some(p) => combine(p, &root),
                None => {
                    let uncle = filler.next(d);
                    combine(&root, &uncle)
                }
            };
            d += 1;
        }
        while d < depth {
            let uncle = filler.next(d);
            root = combine(&root, &uncle);
            d += 1;
        }
        root
    }

    /// The tree's root at full depth.
    pub fn root(&self) -> Node {
        self.root_with(TREE_DEPTH, &mut PathFiller::new(Vec::new()))
    }

    /// The authentication path for the most recently appended leaf, given
    /// the uncles a witness has been collecting.
    ///
    /// Returns `(siblings_leaf_first, position)`.
    fn path_with(&self, uncles: Vec<Node>) -> Result<(Vec<Node>, u64), WitnessError> {
        if self.left.is_none() {
            return Err(WitnessError::EmptyTree);
        }
        let mut filler = PathFiller::new(uncles);
        let mut path = Vec::with_capacity(TREE_DEPTH);
        let mut index_bits = Vec::with_capacity(TREE_DEPTH);

        if self.right.is_some() {
            index_bits.push(true);
            path.push(self.left.expect("left is set"));
        } else {
            index_bits.push(false);
            path.push(filler.next(0));
        }

        let mut d = 1;
        for parent in &self.parents {
            match parent {
                Some(p) => {
                    index_bits.push(true);
                    path.push(*p);
                }
                None => {
                    index_bits.push(false);
                    path.push(filler.next(d));
                }
            }
            d += 1;
        }
        while d < TREE_DEPTH {
            index_bits.push(false);
            path.push(filler.next(d));
            d += 1;
        }

        let mut position: u64 = 0;
        for (i, bit) in index_bits.iter().enumerate() {
            if *bit {
                position |= 1u64 << i;
            }
        }
        Ok((path, position))
    }
}

/// zcashd's `IncrementalWitness<29, SHA256Compress>`.
#[derive(Clone, Debug)]
pub struct IncrementalWitness {
    tree: IncrementalMerkleTree,
    filled: Vec<Node>,
    cursor: Option<IncrementalMerkleTree>,
    cursor_depth: usize,
}

impl IncrementalWitness {
    /// Begin witnessing the most recently appended leaf of `tree`.
    pub fn from_tree(tree: IncrementalMerkleTree) -> Self {
        Self {
            tree,
            filled: Vec::new(),
            cursor: None,
            cursor_depth: 0,
        }
    }

    /// Bring the witness forward past one more appended commitment.
    pub fn append(&mut self, obj: Node) -> Result<(), WitnessError> {
        if let Some(cursor) = self.cursor.as_mut() {
            cursor.append(obj)?;
            if cursor.is_complete(self.cursor_depth) {
                self.filled
                    .push(cursor.root_with(self.cursor_depth, &mut PathFiller::new(Vec::new())));
                self.cursor = None;
            }
        } else {
            self.cursor_depth = self.tree.next_depth(self.filled.len());
            if self.cursor_depth >= TREE_DEPTH {
                return Err(WitnessError::TreeFull);
            }
            if self.cursor_depth == 0 {
                self.filled.push(obj);
            } else {
                let mut cursor = IncrementalMerkleTree::default();
                cursor.append(obj)?;
                self.cursor = Some(cursor);
            }
        }
        Ok(())
    }

    /// The uncles this witness supplies to the tree walk: its filled
    /// subtree roots, plus the partial cursor's root if one is open.
    fn partial_path(&self) -> Vec<Node> {
        let mut uncles = self.filled.clone();
        if let Some(cursor) = &self.cursor {
            uncles.push(cursor.root_with(self.cursor_depth, &mut PathFiller::new(Vec::new())));
        }
        uncles
    }

    /// The anchor this witness authenticates against.
    pub fn root(&self) -> Node {
        self.tree
            .root_with(TREE_DEPTH, &mut PathFiller::new(self.partial_path()))
    }

    /// The authentication path, leaf-first, with the leaf's position.
    pub fn path(&self) -> Result<(Vec<Node>, u64), WitnessError> {
        self.tree.path_with(self.partial_path())
    }

    /// The 966-byte encoding `zcash_proofs::sprout::create_proof` parses.
    ///
    /// Siblings go out root-first, which is the reverse of `path()`'s order:
    /// the prover reads them into `auth_path[28]` down to `auth_path[0]`.
    /// Getting that backwards produces a well-formed buffer that proves a
    /// different tree, so it is asserted in the tests rather than trusted.
    pub fn encode_for_prover(&self) -> Result<[u8; WITNESS_PATH_SIZE], WitnessError> {
        let (path, position) = self.path()?;
        if path.len() != TREE_DEPTH {
            return Err(WitnessError::PathLength(path.len()));
        }

        let mut out = [0u8; WITNESS_PATH_SIZE];
        out[0] = TREE_DEPTH as u8;
        let mut at = 1;
        for sibling in path.iter().rev() {
            out[at] = 32;
            out[at + 1..at + 33].copy_from_slice(sibling);
            at += 33;
        }
        out[at..at + 8].copy_from_slice(&position.to_le_bytes());
        Ok(out)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WitnessError {
    #[error("the Sprout commitment tree is full")]
    TreeFull,
    #[error("cannot build an authentication path for an empty tree")]
    EmptyTree,
    #[error("an authentication path has {0} siblings, expected {TREE_DEPTH}")]
    PathLength(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(n: u8) -> Node {
        let mut node = [0u8; 32];
        node[0] = n;
        node
    }

    /// Fold an authentication path back up to a root, the way the circuit
    /// does. If this disagrees with the tree's own root, the path is wrong
    /// however well-formed it looks.
    fn fold(leaf: Node, path: &[Node], position: u64) -> Node {
        let mut cur = leaf;
        for (i, sibling) in path.iter().enumerate() {
            cur = if (position >> i) & 1 == 1 {
                combine(sibling, &cur)
            } else {
                combine(&cur, sibling)
            };
        }
        cur
    }

    #[test]
    fn empty_roots_are_built_by_doubling() {
        let roots = empty_roots();
        assert_eq!(
            roots[0], [0u8; 32],
            "Sprout's uncommitted leaf is all zeroes"
        );
        assert_eq!(roots[1], combine(&roots[0], &roots[0]));
        assert_ne!(roots[TREE_DEPTH], roots[0]);
    }

    /// The property that matters: a witness's path must reproduce the root
    /// the tree reports. Checked while the witness is the only leaf.
    #[test]
    fn a_path_reproduces_the_root_for_a_single_leaf() {
        let mut tree = IncrementalMerkleTree::default();
        tree.append(leaf(1)).expect("append");
        let witness = IncrementalWitness::from_tree(tree.clone());

        let (path, position) = witness.path().expect("path");
        assert_eq!(path.len(), TREE_DEPTH);
        assert_eq!(position, 0, "the first leaf sits at position 0");
        assert_eq!(fold(leaf(1), &path, position), witness.root());
        assert_eq!(witness.root(), tree.root());
    }

    /// The same property once the witness has been brought forward past
    /// later commitments — the case that actually exercises `filled` and the
    /// cursor, and the case a real wallet witness is always in.
    #[test]
    fn a_path_reproduces_the_root_after_later_appends() {
        let mut tree = IncrementalMerkleTree::default();
        tree.append(leaf(1)).expect("append");
        let mut witness = IncrementalWitness::from_tree(tree.clone());

        for n in 2..=9u8 {
            tree.append(leaf(n)).expect("append");
            witness.append(leaf(n)).expect("witness append");
        }

        let (path, position) = witness.path().expect("path");
        assert_eq!(position, 0, "the witnessed leaf has not moved");
        assert_eq!(
            fold(leaf(1), &path, position),
            witness.root(),
            "the path must still authenticate the original leaf"
        );
        assert_eq!(
            witness.root(),
            tree.root(),
            "the witness must track the tree it came from"
        );
    }

    /// A witness taken over a later leaf must report that leaf's position,
    /// otherwise the prover folds the path the wrong way at every level
    /// where the bit differs.
    #[test]
    fn position_tracks_the_witnessed_leaf() {
        let mut tree = IncrementalMerkleTree::default();
        for n in 1..=5u8 {
            tree.append(leaf(n)).expect("append");
        }
        let witness = IncrementalWitness::from_tree(tree.clone());
        let (path, position) = witness.path().expect("path");
        assert_eq!(position, 4, "the fifth leaf sits at position 4");
        assert_eq!(fold(leaf(5), &path, position), tree.root());
    }

    #[test]
    fn the_prover_encoding_has_the_documented_shape() {
        let mut tree = IncrementalMerkleTree::default();
        tree.append(leaf(1)).expect("append");
        let witness = IncrementalWitness::from_tree(tree);

        let encoded = witness.encode_for_prover().expect("encode");
        assert_eq!(encoded.len(), 966);
        assert_eq!(encoded[0], TREE_DEPTH as u8);
        for i in 0..TREE_DEPTH {
            assert_eq!(encoded[1 + i * 33], 32, "each sibling is length-prefixed");
        }
    }

    /// Siblings are written root-first; the prover reads them into
    /// `auth_path[28]` downwards. Reversing this yields a buffer that parses
    /// and proves the wrong tree.
    #[test]
    fn the_prover_encoding_is_root_first() {
        let mut tree = IncrementalMerkleTree::default();
        for n in 1..=5u8 {
            tree.append(leaf(n)).expect("append");
        }
        let witness = IncrementalWitness::from_tree(tree);
        let (path, _) = witness.path().expect("path");
        let encoded = witness.encode_for_prover().expect("encode");

        let first_serialized = &encoded[2..34];
        assert_eq!(
            first_serialized,
            &path[TREE_DEPTH - 1][..],
            "the first sibling written must be the root-most one"
        );
    }

    #[test]
    fn an_empty_tree_has_no_path() {
        let witness = IncrementalWitness::from_tree(IncrementalMerkleTree::default());
        assert_eq!(witness.path().unwrap_err(), WitnessError::EmptyTree);
    }
}

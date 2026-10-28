# The Sprout pack

A Sprout scan has to read every JoinSplit ever mined. Without a pack it gets
them by downloading every full block over p2p, roughly 280 GB on mainnet.
A Sprout pack holds just those JoinSplits, block by block, up to a fixed
height, so a user can scan from a few gigabytes of files and download only
the blocks after the pack. The result is identical to a full walk.

Users never need a node. Maintainers need one to build the pack.

## Using a pack

- CLI: `argos scan-sprout --sprout-pack <folder> …`
- GUI: Sprout scan panel → "Use a Sprout pack instead of downloading the
  whole chain" → choose the folder.

The folder holds `manifest.bin` and `chunk-0000.bin`, `chunk-0001.bin`, …
On mainnet only a pack whose manifest hash is pinned in `PINNED_PACKS`
(`crates/zeck-core/src/sprout_pack.rs`) for this release is accepted.
Testnet and regtest accept any well-formed pack.

## Format

All integers are little-endian and fixed width. No compression, no
timestamps: the bytes are a pure function of the chain.

**Chunk** `chunk-NNNN.bin` covers heights `N × 100,000 + 1` to
`(N + 1) × 100,000`, the last chunk ending at the pack's end height.

| Field | Bytes |
| --- | --- |
| magic `ARGOSSPC`, format version, network | 8 + 1 + 1 |
| first height, last height | 4 + 4 |
| then for every block: block hash (wire order), JoinSplit count | 32 + 4 |
| then per JoinSplit: txid, index in tx, anchor, 2 nullifiers, 2 commitments, ephemeral key, random seed, JoinSplit pubkey, 2 ciphertexts | 32 + 8 + 32 + 64 + 64 + 32 + 32 + 32 + 1,202 |

Every block appears, including blocks with no JoinSplits (36 bytes each),
so the scanner sees the same contiguous heights a p2p walk gives it and the
pinned checkpoint hashes are checked against the pack.

**Manifest** `manifest.bin`: magic `ARGOSSPM`, format version, network,
chunk size, end height, end block hash, Sprout tree root at the end height,
total JoinSplits, then per chunk its height range, last block hash,
JoinSplit count, byte length and SHA-256. The SHA-256 of this file is what
gets pinned.

## How a scan uses it

1. Open the manifest; refuse a wrong network, and on mainnet an unpinned
   hash.
2. Stream each chunk into the scanner through the same page check a p2p
   page goes through (pinned checkpoints, `TipAnchor`, cursor continuity).
3. At the end of each chunk, compare its length and SHA-256 with the
   manifest. Only then is the scan checkpoint saved. A corrupt chunk
   therefore keeps nothing; a re-run resumes at the last verified chunk.
4. After the last chunk, the rebuilt Sprout tree root must equal the
   manifest's before it is saved.
5. Continue over p2p from the pack's end hash. The cursor reconciliation
   every resumed scan performs asks live peers to confirm that hash first.

## Building a pack (maintainers)

You need a fully synced zcashd or zebrad reachable on its p2p port.

```sh
cargo build --release -p argos-sprout-pack

# End at least 1,000 blocks below your node's tip.
target/release/argos-sprout-pack build \
  --network mainnet --peer 127.0.0.1:8233 \
  --end-height <H> --out sprout-pack-<H>/
```

Only the `--peer` nodes are dialled. Every block passes the scan's own
checks: Equihash proof of work, header linkage, pinned checkpoints, and the
body's txid Merkle root. The build reads the whole chain once, so expect
hours. Interrupt it freely: re-running with the same `--out` reuses every
complete chunk.

When it finishes it prints the manifest SHA-256 and a ready-to-paste
`PINNED_PACKS` entry. `argos-sprout-pack verify --network mainnet <dir>`
re-reads every chunk and prints the same summary.

## Release procedure

1. Pick an end height `H` at least 1,000 blocks below the tip, on a chunk
   boundary or not (fixed boundaries mean earlier chunks are reusable
   across releases either way).
2. Maintainer A builds from their node. Maintainer B builds independently
   from a different node, on a different machine and network.
   **The two manifest SHA-256 values must match.** With zcashd retired,
   the nodes left are Zebra and Zakura, a Zebra fork, so two builds from
   different implementations no longer add much independence.
3. No live node can cross-check the Sprout tree root. zcashd's
   `z_gettreestate` (`sprout.commitments.finalRoot`) was the only RPC that
   returned it; Zebra and Zakura leave the Sprout section out. Record the
   root in the release notes. The builder already checks it: `verify`
   rebuilds the root from the chunks and compares it with the manifest.
4. Check the builder itself, not only the node. Steps 2 and 3 cannot catch
   a builder bug: both maintainers run the same builder, so a bug gives
   both the same hash, and the tree root covers only commitments. A
   swapped nullifier, ciphertext, ephemeral key, `random_seed`, `js_index`
   or txid byte order would pass both and hide notes from every user of
   the release. Before pinning:
   - `cargo test -p argos-core --test sprout_pack_regtest -- --ignored`
     must pass against the regtest Sprout node at the release commit
     (CI's `sprout-node-tests` job runs it on every push);
   - a pack-assisted mainnet scan and a plain p2p scan over the same
     range must agree on the tree root, the cursor, the full nullifier
     set, and the notes found for known test keys.
5. Add the printed entry to `PINNED_PACKS` in
   `crates/zeck-core/src/sprout_pack.rs` and ship it in the release.
6. Upload `manifest.bin` and every chunk as release assets. Each chunk is
   far under GitHub's 2 GiB per-asset limit. Mirrors (CDN, torrent) are
   fine: the pinned hash makes the download source irrelevant.

## Not done yet

- **No equivalence tool.** Step 4's mainnet comparison has to be done by
  hand today; a command that runs both scans and diffs the results is not
  written yet.

- **The first mainnet pin has passed half of step 4.** The pack for blocks 1
  to 3,500,000 (manifest
  `805435e69ae7a28c2045abcb5fa7b049de7e4c288f1f7c3d8d9529eb143ba57d`) was
  built twice on 2026-10-28, from two Zebra 7.0.0 nodes in different
  regions, and both builds produced the same hash. It is pinned. The
  regtest pack test passes (CI runs it on every push), which covers the
  field-level encoding a tree root cannot see: the planted note is found
  from the pack, so `random_seed`, nullifiers, the JoinSplit pubkey, the
  ciphertext, the ephemeral key, `js_index` and txid byte order all
  round-trip. The pack-versus-p2p mainnet comparison is still to run. It
  adds what regtest cannot: the mainnet walk itself, Zebra-specific
  behaviour, and spent-nullifier equivalence. It must pass before a
  release ships with this pin.
- **No in-app download.** Users download the release assets themselves.
  Fetching them from the app needs an HTTP client dependency, which is a
  separate dependency-review decision.
- **P2P only.** The builder reads blocks over p2p. A `getblock` RPC source
  would be faster but needs RPC credentials and a new client.
- **Size.** The mainnet pack to height 3,500,000 is 1.28 GB in 35
  chunks, with 773,651 JoinSplits.

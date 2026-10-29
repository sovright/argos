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
     range must agree on a running digest of every JoinSplit field in
     chain order, the tree root, the cursor, the full nullifier set and
     the notes. `argos-sprout-pack compare --peer <node> --pack <dir>
     --work-dir <new dir>` runs both scans, stopped at the pack's end
     height, and exits non-zero on any difference. The digest is what
     covers the ciphertexts, ephemeral key, `random_seed` and JoinSplit
     pubkey, which otherwise show only as found notes.
5. Add the printed entry to `PINNED_PACKS` in
   `crates/zeck-core/src/sprout_pack.rs`, fill in its `mirrors` (step 6),
   and ship it in the release.
6. Upload `manifest.bin` and every chunk to the public bucket
   `gs://sovright-argos-sprout-packs/sprout-pack/<network>-<end height>-<first
   8 hex of the manifest hash>/` and as release assets. Each chunk is far
   under GitHub's 2 GiB per-asset limit. List both folders in the entry's
   `mirrors`, the bucket first; each must be `https` and end in `/`. Other
   mirrors (CDN, torrent) are fine: the pinned hash makes the download
   source irrelevant. Then run
   `ARGOS_PACK_DIR=<empty dir> cargo test -p argos-core --test
   sprout_pack_fetch_client -- --ignored`, which downloads the pack from
   the live mirrors and verifies it. The GitHub mirror works only once the
   release is published.

## Automatic download

A mainnet Sprout scan with no pack folder downloads the pinned pack itself
(`sprout_pack_fetch`), into `<data dir>/sprout-packs/<network>-<end
height>-<manifest hash>/`, then scans from it:

- The mirrors are not trusted. `manifest.bin` must hash to the pinned value
  before any chunk is requested, and each chunk is written to
  `chunk-NNNN.bin.partial`, capped at the manifest's length, and kept only
  if its length and SHA-256 match. A mirror that fails or serves anything
  else is skipped for the next.
- Finished chunks are re-hashed and reused, so an interrupted download, or a
  later scan, fetches only what is missing.
- It runs only after every check that can stop the scan, and not at all for
  a resumed scan already past the pack's end.
- If every mirror fails, the scan says why and downloads every block over
  p2p, as without a pack.
- Turn it off with `--no-sprout-pack-download` in the CLI or the "Download
  the Sprout pack automatically" setting in the app, or point at a copy you
  downloaded with `--sprout-pack` or the pack folder field.
- Privacy: a mirror sees the IP address of whoever downloads the pack, and a
  download suggests the user holds Sprout funds. Our bucket keeps no access
  logs; the GitHub release is GitHub's. Users who mind can turn the download
  off, or fetch the files another way.

## Pinned packs

- **Mainnet, blocks 1 to 3,500,000** (manifest
  `805435e69ae7a28c2045abcb5fa7b049de7e4c288f1f7c3d8d9529eb143ba57d`,
  first shipped in 1.6.1). Built twice on 2026-10-28, from two Zebra 7.0.0
  nodes in different regions; both builds produced the same hash. Both
  halves of step 4 passed. The regtest pack test passes (CI runs it on
  every push). The mainnet comparison passed on 2026-10-29: run with
  `argos-sprout-pack compare` against a Zebra 7.0.0 node, the pack scan
  and the p2p scan of heights 1 to 3,500,000 matched on the JoinSplit
  digest (773,651 JoinSplits, digest
  `80629826a3a5e074b6ba4bbe4db0e893bfdcfba0f2cff7e64d13d5ffb5728ffd`),
  the tree root, the cursor, progress, the spent nullifiers and the
  notes.

## Not done yet

- **`compare` does not resume.** Both scans start from an empty
  directory, so an interrupted p2p scan starts again from height 1.
- **P2P only.** The builder reads blocks over p2p. A `getblock` RPC source
  would be faster but needs RPC credentials and a new client.
- **Size.** The mainnet pack to height 3,500,000 is 1.28 GB in 35
  chunks, with 773,651 JoinSplits.

"""Rekor transparency log verifier: inclusion and consistency checks."""

import argparse
import base64
import json
import os
import sys
from typing import Any

import requests

from merkle_proof import (
    DefaultHasher,
    RootMismatchError,
    compute_leaf_hash,
    verify_consistency,
    verify_inclusion,
)
from util import extract_public_key, verify_artifact_signature

REKOR_BASE_URL = "https://rekor.sigstore.dev/api/v1"
REQUEST_TIMEOUT = 10  # seconds
DEBUG_OUTPUT_DIR = "debug_output"  # listed in .gitignore

Checkpoint = dict[str, Any]


class VerificationError(Exception):
    """A signature, inclusion or consistency check did not pass."""


def _write_debug_file(filename: str, data: Any) -> None:
    """Save debug JSON under DEBUG_OUTPUT_DIR instead of the working directory."""
    os.makedirs(DEBUG_OUTPUT_DIR, exist_ok=True)
    path = os.path.join(DEBUG_OUTPUT_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    print(f"Saved debug output to {path}")


def _validate_log_index(log_index: int) -> None:
    if not isinstance(log_index, int) or isinstance(log_index, bool):
        raise ValueError(
            f"log index must be an integer, got {type(log_index).__name__}"
        )
    if log_index < 0:
        raise ValueError(f"log index must be non-negative, got {log_index}")


def get_log_entry(log_index: int, debug: bool = False) -> dict[str, Any]:
    """Fetch the entry at log_index from Rekor (the value under its UUID key)."""
    _validate_log_index(log_index)

    resp = requests.get(
        f"{REKOR_BASE_URL}/log/entries",
        params={"logIndex": log_index},
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    data: dict[str, Any] = resp.json()

    # response: { "<uuid>": { body, integratedTime, logID, logIndex, verification } }
    if not data:
        raise ValueError(f"no entry found for log index {log_index}")
    uuid, entry = next(iter(data.items()))
    if not isinstance(entry, dict):
        raise ValueError("unexpected log entry format from Rekor")

    if debug:
        print(f"Fetched entry {uuid} for log index {log_index}")
        _write_debug_file("log_entry.json", data)

    return entry


def get_verification_proof(
    log_index: int,
    debug: bool = False,
    entry: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the leaf hash and inclusion proof for the entry at log_index.

    Pass an already-fetched entry to avoid requesting it from Rekor again.
    """
    _validate_log_index(log_index)
    if entry is None:
        entry = get_log_entry(log_index, debug)

    proof = entry["verification"]["inclusionProof"]
    verification = {
        # shard-local index, not the global log index
        "index": proof["logIndex"],
        "tree_size": proof["treeSize"],
        "root_hash": proof["rootHash"],
        "hashes": proof["hashes"],
        "leaf_hash": compute_leaf_hash(entry["body"]),
    }

    if debug:
        print("Inclusion proof:")
        print(json.dumps(verification, indent=4))

    return verification


def inclusion(log_index: int, artifact_filepath: str, debug: bool = False) -> None:
    """Verify the artifact's signature and the entry's inclusion proof.

    Raises VerificationError if either check fails.
    """
    _validate_log_index(log_index)
    if not artifact_filepath:
        raise ValueError("please specify an artifact filepath with --artifact")
    if not os.path.isfile(artifact_filepath):
        raise FileNotFoundError(f"artifact not found: {artifact_filepath}")

    # fetch the entry once and decode its body (base64-encoded JSON)
    entry = get_log_entry(log_index, debug)
    body = json.loads(base64.b64decode(entry["body"]))

    # hashedrekord layout: spec.signature.content           -> DER signature
    #                      spec.signature.publicKey.content -> PEM certificate
    sig_info = body["spec"]["signature"]
    signature = base64.b64decode(sig_info["content"])
    certificate = base64.b64decode(sig_info["publicKey"]["content"])

    public_key = extract_public_key(certificate)
    if debug:
        print("Extracted public key:")
        print(public_key.decode())

    if not verify_artifact_signature(signature, public_key, artifact_filepath):
        raise VerificationError(
            f"signature in log entry {log_index} is not valid for {artifact_filepath}"
        )
    print("Signature is valid.")

    proof = get_verification_proof(log_index, debug, entry=entry)
    try:
        verify_inclusion(
            DefaultHasher,
            proof["index"],
            proof["tree_size"],
            proof["leaf_hash"],
            proof["hashes"],
            proof["root_hash"],
            debug,
        )
    except RootMismatchError as e:
        raise VerificationError(f"inclusion proof did not verify: {e}") from e
    print("Offline root hash calculation for inclusion verified.")


def get_latest_checkpoint(debug: bool = False) -> Checkpoint:
    """Fetch the latest signed checkpoint (tree head) from Rekor."""
    resp = requests.get(f"{REKOR_BASE_URL}/log", timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    checkpoint: Checkpoint = resp.json()

    if debug:
        _write_debug_file("checkpoint.json", checkpoint)

    return checkpoint


def _validate_prev_checkpoint(prev_checkpoint: Checkpoint) -> None:
    if not prev_checkpoint:
        raise ValueError("previous checkpoint is empty")
    for key in ("treeID", "treeSize", "rootHash"):
        if not prev_checkpoint.get(key):
            raise ValueError(f"previous checkpoint is missing {key}")

    tree_id = str(prev_checkpoint["treeID"])
    if not tree_id.isdigit():
        raise ValueError(f"tree id must be numeric, got {tree_id!r}")

    tree_size = prev_checkpoint["treeSize"]
    if not isinstance(tree_size, int) or tree_size <= 0:
        raise ValueError(f"tree size must be a positive integer, got {tree_size!r}")

    root_hash = prev_checkpoint["rootHash"]
    try:
        root_bytes = bytes.fromhex(root_hash)
    except ValueError:
        raise ValueError(f"root hash is not valid hex: {root_hash!r}") from None
    if len(root_bytes) != DefaultHasher.size():
        raise ValueError(
            f"root hash should be {DefaultHasher.size()} bytes, got {len(root_bytes)}"
        )


def _checkpoint_for_tree(prev_checkpoint: Checkpoint, latest: Checkpoint) -> Checkpoint:
    """Pick the checkpoint for the previous checkpoint's tree, which may be an
    inactive shard listed under inactiveShards."""
    tree_id = str(prev_checkpoint["treeID"])
    if str(latest["treeID"]) == tree_id:
        return latest
    shards: list[Checkpoint] = latest.get("inactiveShards") or []
    for shard in shards:
        if str(shard.get("treeID")) == tree_id:
            print(
                f"Tree {tree_id} is an inactive shard; "
                "verifying against its final checkpoint."
            )
            return shard
    raise ValueError(
        f"tree id {tree_id} not found in the latest checkpoint "
        f"(active tree is {latest['treeID']})"
    )


def get_consistency_proof(
    first_size: int, last_size: int, tree_id: str, debug: bool = False
) -> dict[str, Any]:
    """Fetch the consistency proof between two tree sizes from Rekor."""
    resp = requests.get(
        f"{REKOR_BASE_URL}/log/proof",
        params={
            "firstSize": str(first_size),
            "lastSize": str(last_size),
            "treeID": str(tree_id),
        },
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    proof: dict[str, Any] = resp.json()

    if debug:
        print(f"Consistency proof ({first_size} -> {last_size}):")
        print(json.dumps(proof, indent=4))

    return proof


def consistency(prev_checkpoint: Checkpoint, debug: bool = False) -> None:
    """Verify that prev_checkpoint is consistent with the latest checkpoint.

    Raises VerificationError if it is not.
    """
    _validate_prev_checkpoint(prev_checkpoint)

    latest = get_latest_checkpoint(debug)
    target = _checkpoint_for_tree(prev_checkpoint, latest)

    size1 = prev_checkpoint["treeSize"]
    size2 = int(target["treeSize"])
    root1 = prev_checkpoint["rootHash"]
    root2 = target["rootHash"]

    if debug:
        print(f"Older checkpoint:  size={size1} root={root1}")
        print(f"Latest checkpoint: size={size2} root={root2}")

    # an append-only log can never shrink
    if size2 < size1:
        raise VerificationError(
            f"latest tree size ({size2}) is smaller than the older one ({size1})"
        )

    if size1 == size2:
        # nothing to prove: the roots must simply match
        print(
            "Warning: both checkpoints have the same tree size. Use an older "
            "checkpoint (or wait for the log to grow) for a meaningful check."
        )
        hashes: list[str] = []
    else:
        proof = get_consistency_proof(size1, size2, prev_checkpoint["treeID"], debug)
        hashes = proof["hashes"]

    try:
        verify_consistency(DefaultHasher, size1, size2, hashes, root1, root2)
    except (RootMismatchError, ValueError) as e:
        raise VerificationError(f"consistency proof did not verify: {e}") from e
    print("Consistency verification successful.")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument(
        "-d",
        "--debug",
        help=f"Debug mode (writes JSON files to {DEBUG_OUTPUT_DIR}/)",
        required=False,
        action="store_true",
    )
    parser.add_argument(
        "-c",
        "--checkpoint",
        help="Obtain latest checkpoint\
                        from Rekor Server public instance",
        required=False,
        action="store_true",
    )
    parser.add_argument(
        "--inclusion",
        help="Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567 --artifact artifact.md",
        required=False,
        type=int,
    )
    parser.add_argument(
        "--artifact",
        help="Artifact filepath for verifying\
                        signature",
        required=False,
    )
    parser.add_argument(
        "--consistency",
        help="Verify consistency of a given\
                        checkpoint with the latest checkpoint.",
        action="store_true",
    )
    parser.add_argument(
        "--tree-id", help="Tree ID for consistency proof", required=False
    )
    parser.add_argument(
        "--tree-size", help="Tree size for consistency proof", required=False, type=int
    )
    parser.add_argument(
        "--root-hash", help="Root hash for consistency proof", required=False
    )
    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    # validate argument combinations up front; parser.error prints usage and exits 2
    if args.inclusion is not None and not args.artifact:
        parser.error("--inclusion requires --artifact")
    if args.artifact and args.inclusion is None:
        parser.error("--artifact is only used together with --inclusion")
    if args.consistency:
        missing = [
            flag
            for flag, value in (
                ("--tree-id", args.tree_id),
                ("--tree-size", args.tree_size),
                ("--root-hash", args.root_hash),
            )
            if not value
        ]
        if missing:
            parser.error(f"--consistency requires {', '.join(missing)}")
    if not (args.checkpoint or args.inclusion is not None or args.consistency):
        parser.error("specify at least one of -c, --inclusion or --consistency")

    debug = args.debug
    if debug:
        print("enabled debug mode")

    try:
        if args.checkpoint:
            checkpoint = get_latest_checkpoint(debug)
            print(json.dumps(checkpoint, indent=4))
        if args.inclusion is not None:
            inclusion(args.inclusion, args.artifact, debug)
        if args.consistency:
            prev_checkpoint: Checkpoint = {
                "treeID": args.tree_id,
                "treeSize": args.tree_size,
                "rootHash": args.root_hash,
            }
            consistency(prev_checkpoint, debug)
    except VerificationError as e:
        print(f"Verification failed: {e}", file=sys.stderr)
        sys.exit(1)
    except requests.RequestException as e:
        print(f"Error contacting Rekor: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyError as e:
        print(
            f"Error: unexpected response from Rekor, missing field {e}", file=sys.stderr
        )
        sys.exit(1)
    except (ValueError, OSError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

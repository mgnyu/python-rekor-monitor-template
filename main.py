import argparse
import base64
import json
import os

import requests

from util import extract_public_key, verify_artifact_signature
from merkle_proof import (
    DefaultHasher,
    verify_consistency,
    verify_inclusion,
    compute_leaf_hash,
    RootMismatchError,
)

REKOR_BASE_URL = "https://rekor.sigstore.dev/api/v1"
REQUEST_TIMEOUT = 10

def _validate_log_index(log_index):
    if not isinstance(log_index, int) or isinstance(log_index, bool):
        raise ValueError(f"log index must be an integer, got {type(log_index).__name__}")
    if log_index < 0:
        raise ValueError(f"log index must be non-negative, got {log_index}")


def get_log_entry(log_index, debug=False):
    _validate_log_index(log_index)

    resp = requests.get(
        f"{REKOR_BASE_URL}/log/entries",
        params={"logIndex": log_index},
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    data = resp.json()

    # response: { "<uuid>": { body, integratedTime, logID, logIndex, verification } }
    if not data:
        raise ValueError(f"no entry found for log index {log_index}")
    uuid, entry = next(iter(data.items()))

    if debug:
        print(f"Fetched entry {uuid} for log index {log_index}")
        with open("log_entry.json", "w") as f:
            json.dump(data, f, indent=4)
        print("Saved raw entry to log_entry.json")

    return entry


def get_verification_proof(log_index, debug=False):
    """Return the leaf hash and inclusion proof fields for the entry at log_index."""
    _validate_log_index(log_index)

    entry = get_log_entry(log_index, debug)
    proof = entry["verification"]["inclusionProof"]

    verification = {
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


def inclusion(log_index, artifact_filepath, debug=False):
    # verify that log index and artifact filepath values are sane
    _validate_log_index(log_index)
    if not artifact_filepath:
        raise ValueError("please specify an artifact filepath with --artifact")
    if not os.path.isfile(artifact_filepath):
        raise FileNotFoundError(f"artifact not found: {artifact_filepath}")

    # fetch the entry and decode its body (base64-encoded JSON)
    entry = get_log_entry(log_index, debug)
    body = json.loads(base64.b64decode(entry["body"]))

    # extract signature and certificate (both base64-encoded)
    # hashed rekord layout:   spec.signature.content           -> DER signature
    #                         spec.signature.publicKey.content -> PEM certificate
    sig_info = body["spec"]["signature"]
    signature = base64.b64decode(sig_info["content"])
    certificate = base64.b64decode(sig_info["publicKey"]["content"])

    public_key = extract_public_key(certificate)
    if debug:
        print("Extracted public key:")
        print(public_key.decode())

    # verify the artifact signature (util prints a message on failure)
    verify_artifact_signature(signature, public_key, artifact_filepath)

    # verify the inclusion proof
    proof = get_verification_proof(log_index, debug)
    verify_inclusion(
        DefaultHasher,
        proof["index"],
        proof["tree_size"],
        proof["leaf_hash"],
        proof["hashes"],
        proof["root_hash"],
        debug,
    )
    print("Offline root hash calculation for inclusion verified.")


def get_latest_checkpoint(debug=False):
    resp = requests.get(f"{REKOR_BASE_URL}/log", timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    checkpoint = resp.json()

    if debug:
        with open("checkpoint.json", "w") as f:
            json.dump(checkpoint, f, indent=4)
        print("Saved latest checkpoint to checkpoint.json")

    return checkpoint


def _validate_prev_checkpoint(prev_checkpoint):
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
        raise ValueError(f"root hash is not valid hex: {root_hash!r}")
    if len(root_bytes) != DefaultHasher.size():
        raise ValueError(
            f"root hash should be {DefaultHasher.size()} bytes, got {len(root_bytes)}"
        )


def _checkpoint_for_tree(prev_checkpoint, latest):
    tree_id = str(prev_checkpoint["treeID"])
    if str(latest["treeID"]) == tree_id:
        return latest
    for shard in latest.get("inactiveShards") or []:
        if str(shard.get("treeID")) == tree_id:
            print(f"Tree {tree_id} is an inactive shard; "
                  "verifying against its final checkpoint.")
            return shard
    raise ValueError(
        f"tree id {tree_id} not found in the latest checkpoint "
        f"(active tree is {latest['treeID']})"
    )


def get_consistency_proof(first_size, last_size, tree_id, debug=False):
    resp = requests.get(
        f"{REKOR_BASE_URL}/log/proof",
        params={"firstSize": first_size, "lastSize": last_size, "treeID": tree_id},
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    proof = resp.json()

    if debug:
        print(f"Consistency proof ({first_size} -> {last_size}):")
        print(json.dumps(proof, indent=4))

    return proof


def consistency(prev_checkpoint, debug=False):
    # verify that prev checkpoint is not empty and well formed
    _validate_prev_checkpoint(prev_checkpoint)

    # fetch the latest checkpoint and find the matching tree
    latest = get_latest_checkpoint(debug)
    target = _checkpoint_for_tree(prev_checkpoint, latest)

    size1 = prev_checkpoint["treeSize"]
    size2 = int(target["treeSize"])
    root1 = prev_checkpoint["rootHash"]
    root2 = target["rootHash"]

    if debug:
        print(f"Older checkpoint:  size={size1} root={root1}")
        print(f"Latest checkpoint: size={size2} root={root2}")

    # An append-only log can never shrink
    if size2 < size1:
        print(f"Consistency verification failed: latest tree size ({size2}) "
              f"is smaller than the older one ({size1}).")
        return

    # Same size: nothing to prove, the roots must simply match
    if size1 == size2:
        print("Warning: both checkpoints have the same tree size. Use an older "
              "checkpoint (or wait for the log to grow) for a meaningful check.")
        try:
            verify_consistency(DefaultHasher, size1, size2, [], root1, root2)
        except RootMismatchError as e:
            print("Consistency verification failed:", e)
            return
        print("Consistency verification successful (identical checkpoints).")
        return

    # get the consistency proof from Rekor
    proof = get_consistency_proof(size1, size2, prev_checkpoint["treeID"], debug)

    # verify it locally
    try:
        verify_consistency(DefaultHasher, size1, size2, proof["hashes"], root1, root2)
    except (RootMismatchError, ValueError) as e:
        print("Consistency verification failed:", e)
        return
    print("Consistency verification successful.")


def main():
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument('-d', '--debug', help='Debug mode',
                        required=False, action='store_true')  # Default false
    parser.add_argument('-c', '--checkpoint', help='Obtain latest checkpoint\
                        from Rekor Server public instance',
                        required=False, action='store_true')
    parser.add_argument('--inclusion', help='Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567',
                        required=False, type=int)
    parser.add_argument('--artifact', help='Artifact filepath for verifying\
                        signature',
                        required=False)
    parser.add_argument('--consistency', help='Verify consistency of a given\
                        checkpoint with the latest checkpoint.',
                        action='store_true')
    parser.add_argument('--tree-id', help='Tree ID for consistency proof',
                        required=False)
    parser.add_argument('--tree-size', help='Tree size for consistency proof',
                        required=False, type=int)
    parser.add_argument('--root-hash', help='Root hash for consistency proof',
                        required=False)
    args = parser.parse_args()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))
    if args.inclusion is not None:
        inclusion(args.inclusion, args.artifact, debug)
    if args.consistency:
        if not args.tree_id:
            print("please specify tree id for prev checkpoint")
            return
        if not args.tree_size:
            print("please specify tree size for prev checkpoint")
            return
        if not args.root_hash:
            print("please specify root hash for prev checkpoint")
            return

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        consistency(prev_checkpoint, debug)


if __name__ == "__main__":
    main()

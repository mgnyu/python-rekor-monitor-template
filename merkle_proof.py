import base64
import binascii
import hashlib
from collections.abc import Callable, Sequence
from typing import Any

# domain separation prefixes according to the RFC
RFC6962_LEAF_HASH_PREFIX = 0
RFC6962_NODE_HASH_PREFIX = 1

HashFactory = Callable[[], Any]


class Hasher:
    def __init__(self, hash_func: HashFactory = hashlib.sha256) -> None:
        self.hash_func = hash_func

    def new(self) -> Any:
        return self.hash_func()

    def empty_root(self) -> bytes:
        digest: bytes = self.new().digest()
        return digest

    def hash_leaf(self, leaf: bytes) -> bytes:
        h = self.new()
        h.update(bytes([RFC6962_LEAF_HASH_PREFIX]))
        h.update(leaf)
        digest: bytes = h.digest()
        return digest

    def hash_children(self, left: bytes, right: bytes) -> bytes:
        h = self.new()
        h.update(bytes([RFC6962_NODE_HASH_PREFIX]) + left + right)
        digest: bytes = h.digest()
        return digest

    def size(self) -> int:
        digest_size: int = self.new().digest_size
        return digest_size


# DefaultHasher is a SHA256 based LogHasher
DefaultHasher = Hasher(hashlib.sha256)


class RootMismatchError(Exception):
    def __init__(self, expected_root: bytes, calculated_root: bytes) -> None:
        super().__init__()
        self.expected_root = binascii.hexlify(bytearray(expected_root))
        self.calculated_root = binascii.hexlify(bytearray(calculated_root))

    def __str__(self) -> str:
        return (
            f"calculated root:\n{self.calculated_root.decode()}\n"
            f" does not match expected root:\n{self.expected_root.decode()}"
        )


def verify_consistency(
    hasher: Hasher,
    size1: int,
    size2: int,
    proof: Sequence[str],
    root1: str,
    root2: str,
) -> None:
    # change format of args to be bytes instead of hex strings
    root1_bytes = bytes.fromhex(root1)
    root2_bytes = bytes.fromhex(root2)
    bytearray_proof = [bytes.fromhex(elem) for elem in proof]

    if size2 < size1:
        raise ValueError(f"size2 ({size2}) < size1 ({size1})")
    if size1 == size2:
        if bytearray_proof:
            raise ValueError("size1=size2, but bytearray_proof is not empty")
        verify_match(root1_bytes, root2_bytes)
        return
    if size1 == 0:
        if bytearray_proof:
            raise ValueError(
                "expected empty bytearray_proof, "
                f"but got {len(bytearray_proof)} components"
            )
        return
    if not bytearray_proof:
        raise ValueError("empty bytearray_proof")

    inner, border = decomp_incl_proof(size1 - 1, size2)
    shift = (size1 & -size1).bit_length() - 1
    inner -= shift

    if size1 == 1 << shift:
        seed, start = root1_bytes, 0
    else:
        seed, start = bytearray_proof[0], 1

    if len(bytearray_proof) != start + inner + border:
        raise ValueError(
            f"wrong bytearray_proof size {len(bytearray_proof)}, "
            f"want {start + inner + border}"
        )

    bytearray_proof = bytearray_proof[start:]

    mask = (size1 - 1) >> shift
    hash1 = chain_inner_right(hasher, seed, bytearray_proof[:inner], mask)
    hash1 = chain_border_right(hasher, hash1, bytearray_proof[inner:])
    verify_match(hash1, root1_bytes)

    hash2 = chain_inner(hasher, seed, bytearray_proof[:inner], mask)
    hash2 = chain_border_right(hasher, hash2, bytearray_proof[inner:])
    verify_match(hash2, root2_bytes)


def verify_match(calculated: bytes, expected: bytes) -> None:
    if calculated != expected:
        raise RootMismatchError(expected, calculated)


def decomp_incl_proof(index: int, size: int) -> tuple[int, int]:
    inner = inner_proof_size(index, size)
    border = bin(index >> inner).count("1")
    return inner, border


def inner_proof_size(index: int, size: int) -> int:
    return (index ^ (size - 1)).bit_length()


def chain_inner(
    hasher: Hasher, seed: bytes, proof: Sequence[bytes], index: int
) -> bytes:
    for i, h in enumerate(proof):
        if (index >> i) & 1 == 0:
            seed = hasher.hash_children(seed, h)
        else:
            seed = hasher.hash_children(h, seed)
    return seed


def chain_inner_right(
    hasher: Hasher, seed: bytes, proof: Sequence[bytes], index: int
) -> bytes:
    for i, h in enumerate(proof):
        if (index >> i) & 1 == 1:
            seed = hasher.hash_children(h, seed)
    return seed


def chain_border_right(hasher: Hasher, seed: bytes, proof: Sequence[bytes]) -> bytes:
    for h in proof:
        seed = hasher.hash_children(h, seed)
    return seed


def root_from_inclusion_proof(
    hasher: Hasher, index: int, size: int, leaf_hash: bytes, proof: Sequence[bytes]
) -> bytes:
    if index >= size:
        raise ValueError(f"index is beyond size: {index} >= {size}")

    if len(leaf_hash) != hasher.size():
        raise ValueError(
            f"leaf_hash has unexpected size {len(leaf_hash)}, want {hasher.size()}"
        )

    inner, border = decomp_incl_proof(index, size)
    if len(proof) != inner + border:
        raise ValueError(f"wrong proof size {len(proof)}, want {inner + border}")

    res = chain_inner(hasher, leaf_hash, proof[:inner], index)
    res = chain_border_right(hasher, res, proof[inner:])
    return res


def verify_inclusion(
    hasher: Hasher,
    index: int,
    size: int,
    leaf_hash: str,
    proof: Sequence[str],
    root: str,
    debug: bool = False,
) -> None:
    bytearray_proof = [bytes.fromhex(elem) for elem in proof]
    bytearray_root = bytes.fromhex(root)
    bytearray_leaf = bytes.fromhex(leaf_hash)
    calc_root = root_from_inclusion_proof(
        hasher, index, size, bytearray_leaf, bytearray_proof
    )
    verify_match(calc_root, bytearray_root)
    if debug:
        print("Calculated root hash", calc_root.hex())
        print("Given root hash", bytearray_root.hex())


def compute_leaf_hash(body: str) -> str:
    entry_bytes = base64.b64decode(body)
    h = hashlib.sha256()
    h.update(bytes([RFC6962_LEAF_HASH_PREFIX]))
    h.update(entry_bytes)
    return h.hexdigest()

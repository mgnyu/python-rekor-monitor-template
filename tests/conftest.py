import base64
import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
import requests

import main
from merkle_proof import DefaultHasher

REPO_ROOT = Path(__file__).resolve().parent.parent


def b64_to_hex(value: str) -> str:
    return base64.b64decode(value).hex()


@pytest.fixture
def real_entry() -> dict[str, Any]:
    bundle = json.loads((REPO_ROOT / "artifact.bundle.json").read_text())
    tlog = bundle["verificationMaterial"]["tlogEntries"][0]
    proof = tlog["inclusionProof"]
    return {
        "body": tlog["canonicalizedBody"],
        "logIndex": int(tlog["logIndex"]),
        "verification": {
            "inclusionProof": {
                "logIndex": int(proof["logIndex"]),
                "treeSize": int(proof["treeSize"]),
                "rootHash": b64_to_hex(proof["rootHash"]),
                "hashes": [b64_to_hex(h) for h in proof["hashes"]],
            }
        },
    }


@pytest.fixture
def artifact_path() -> Path:
    return REPO_ROOT / "artifact.md"


@pytest.fixture
def small_tree() -> dict[str, Any]:
    leaf1 = DefaultHasher.hash_leaf(b"first entry")
    leaf2 = DefaultHasher.hash_leaf(b"second entry")
    return {
        "tree_id": "1193050959916656506",
        "root1": leaf1.hex(),
        "root2": DefaultHasher.hash_children(leaf1, leaf2).hex(),
        "proof": [leaf2.hex()],
    }


class FakeResponse:
    def __init__(self, payload: Any) -> None:
        self.payload = payload

    def raise_for_status(self) -> None:
        pass

    def json(self) -> Any:
        return self.payload


class FakeRekor:
    def __init__(self) -> None:
        self.responses: dict[str, Any] = {}
        self.calls: list[str] = []
        self.fail_with: Exception | None = None

    def get(
        self, url: str, params: dict[str, Any] | None = None, timeout: float = 0
    ) -> FakeResponse:
        self.calls.append(url)
        if self.fail_with is not None:
            raise self.fail_with
        return FakeResponse(self.responses[url.removeprefix(main.REKOR_BASE_URL)])

    def count(self, endpoint: str) -> int:
        return sum(url.endswith(endpoint) for url in self.calls)


@pytest.fixture
def rekor(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeRekor]:
    fake = FakeRekor()
    monkeypatch.setattr(requests, "get", fake.get)
    yield fake


@pytest.fixture
def run_cli(monkeypatch: pytest.MonkeyPatch) -> Callable[..., int]:
    def _run(*args: str) -> int:
        monkeypatch.setattr("sys.argv", ["main.py", *args])
        try:
            main.main()
        except SystemExit as exc:
            return int(exc.code or 0)
        return 0

    return _run


@pytest.fixture(autouse=True)
def isolated_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)

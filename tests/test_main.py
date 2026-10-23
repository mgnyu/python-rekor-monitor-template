import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import requests

from tests.conftest import FakeRekor

CHECKPOINT = {"treeID": "1193050959916656506", "treeSize": 2, "rootHash": ""}


def consistency_args(tree_id: str, size: int, root: str) -> list[str]:
    return [
        "--consistency",
        "--tree-id",
        tree_id,
        "--tree-size",
        str(size),
        "--root-hash",
        root,
    ]


def test_checkpoint_flag_prints_latest_checkpoint(
    rekor: FakeRekor, run_cli: Callable[..., int], capsys: pytest.CaptureFixture[str]
) -> None:
    rekor.responses["/log"] = CHECKPOINT
    assert run_cli("-c") == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["treeID"] == CHECKPOINT["treeID"]
    assert printed["treeSize"] == CHECKPOINT["treeSize"]


def test_debug_writes_into_debug_output_dir(
    rekor: FakeRekor, run_cli: Callable[..., int], tmp_path: Path
) -> None:
    rekor.responses["/log"] = CHECKPOINT
    assert run_cli("-d", "-c") == 0
    assert (tmp_path / "debug_output" / "checkpoint.json").is_file()
    assert not (tmp_path / "checkpoint.json").exists()


def test_inclusion_succeeds_for_real_artifact(
    rekor: FakeRekor,
    run_cli: Callable[..., int],
    real_entry: dict[str, Any],
    artifact_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rekor.responses["/log/entries"] = {"uuid": real_entry}
    index = str(real_entry["logIndex"])
    assert run_cli("-d", "--inclusion", index, "--artifact", str(artifact_path)) == 0
    out = capsys.readouterr().out
    assert "Signature is valid" in out
    assert "inclusion verified" in out
    assert rekor.count("/log/entries") == 1  # entry is fetched only once


def test_inclusion_fails_for_tampered_artifact(
    rekor: FakeRekor,
    run_cli: Callable[..., int],
    real_entry: dict[str, Any],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fake = tmp_path / "fake.md"
    fake.write_text("tampered\n")
    rekor.responses["/log/entries"] = {"uuid": real_entry}
    index = str(real_entry["logIndex"])
    assert run_cli("--inclusion", index, "--artifact", str(fake)) == 1
    assert "Verification failed" in capsys.readouterr().err


def test_inclusion_without_artifact_is_a_usage_error(
    run_cli: Callable[..., int], capsys: pytest.CaptureFixture[str]
) -> None:
    assert run_cli("--inclusion", "5") == 2
    assert "--inclusion requires --artifact" in capsys.readouterr().err


def test_consistency_succeeds(
    rekor: FakeRekor,
    run_cli: Callable[..., int],
    small_tree: dict[str, Any],
    capsys: pytest.CaptureFixture[str],
) -> None:
    rekor.responses["/log"] = {**CHECKPOINT, "rootHash": small_tree["root2"]}
    rekor.responses["/log/proof"] = {"hashes": small_tree["proof"]}
    args = consistency_args(small_tree["tree_id"], 1, small_tree["root1"])
    assert run_cli("-d", *args) == 0
    assert "Consistency verification successful" in capsys.readouterr().out


def test_consistency_fails_for_wrong_old_root(
    rekor: FakeRekor,
    run_cli: Callable[..., int],
    small_tree: dict[str, Any],
    capsys: pytest.CaptureFixture[str],
) -> None:
    rekor.responses["/log"] = {**CHECKPOINT, "rootHash": small_tree["root2"]}
    rekor.responses["/log/proof"] = {"hashes": small_tree["proof"]}
    assert run_cli(*consistency_args(small_tree["tree_id"], 1, "ab" * 32)) == 1
    assert "consistency proof did not verify" in capsys.readouterr().err


def test_consistency_detects_shrinking_log(
    rekor: FakeRekor,
    run_cli: Callable[..., int],
    small_tree: dict[str, Any],
    capsys: pytest.CaptureFixture[str],
) -> None:
    rekor.responses["/log"] = {**CHECKPOINT, "rootHash": small_tree["root2"]}
    assert (
        run_cli(*consistency_args(small_tree["tree_id"], 5, small_tree["root1"])) == 1
    )
    assert "smaller" in capsys.readouterr().err
    assert rekor.count("/log/proof") == 0


def test_invalid_root_hash_is_rejected_before_network_call(
    rekor: FakeRekor, run_cli: Callable[..., int], capsys: pytest.CaptureFixture[str]
) -> None:
    assert run_cli(*consistency_args("1193050959916656506", 5, "zz")) == 1
    assert "root hash is not valid hex" in capsys.readouterr().err
    assert rekor.calls == []


def test_network_error_exits_1(
    rekor: FakeRekor, run_cli: Callable[..., int], capsys: pytest.CaptureFixture[str]
) -> None:
    rekor.fail_with = requests.ConnectionError("connection refused")
    assert run_cli("-c") == 1
    assert "Error contacting Rekor" in capsys.readouterr().err

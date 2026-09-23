"""Tests for the CLI, in particular the --fail-under policy gate.

The gate is what makes this tool usable as a CI step, so its exit codes are
part of the contract: 0 means the pipeline continues, 1 means it stops.
"""

from __future__ import annotations

import json

import pytest

from hardening_check.cli import main

from test_checker import ELFBuilder


@pytest.fixture
def weak_elf(tmp_path):
    """PIE, but no NX, no canary and no RELRO — scores 1/4.

    PT_INTERP is what makes this a PIE rather than a plain shared object.
    """
    path = tmp_path / "weak.elf"
    path.write_bytes(ELFBuilder(pie=True).add_interp().build().getvalue())
    return str(path)


@pytest.fixture
def hardened_elf(tmp_path):
    """PIE + NX + canary + full RELRO — scores 4/4."""
    path = tmp_path / "hardened.elf"
    builder = (
        ELFBuilder(pie=True)
        .add_interp()
        .add_gnu_stack(executable=False)
        .add_gnu_relro()
    )
    path.write_bytes(builder.build().getvalue())
    return str(path)


def test_no_gate_exits_zero(weak_elf, capsys):
    """Without --fail-under, a weak binary is reported but does not fail."""
    main([weak_elf])
    # The table truncates long paths, so assert on the stable header instead.
    assert "ELF Hardening Report" in capsys.readouterr().out


def test_gate_fails_below_threshold(weak_elf, capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--fail-under", "4", weak_elf])
    assert exc.value.code == 1
    assert "FAIL" in capsys.readouterr().err


def test_gate_passes_at_threshold(weak_elf):
    """Score 1 with a threshold of 1 passes — the check is `<`, not `<=`."""
    main(["--fail-under", "1", weak_elf])


def test_gate_ignores_non_elf(tmp_path):
    """A non-ELF file carries no score and must not trip the gate."""
    path = tmp_path / "notes.txt"
    path.write_text("not a binary")
    main(["--fail-under", "4", str(path)])


def test_json_output_is_valid(weak_elf, capsys):
    main(["--json", weak_elf])
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["is_elf"] is True
    assert payload[0]["score"] == 1
    assert payload[0]["relro"] == "None"

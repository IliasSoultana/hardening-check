"""CLI entry point for hardening-check."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich import box

from hardening_check.checker import HardeningResult, analyze_many

console = Console()


def _bool_cell(value: bool | None, *, good_is_true: bool = True) -> str:
    if value is None:
        return "[dim]N/A[/dim]"
    if value == good_is_true:
        return "[bold green]YES[/bold green]"
    return "[bold red]NO[/bold red]"


def _relro_cell(value: str | None) -> str:
    if value is None:
        return "[dim]N/A[/dim]"
    colors = {"Full": "bold green", "Partial": "yellow", "None": "bold red"}
    color = colors.get(value, "white")
    return f"[{color}]{value}[/{color}]"


def _score(result: HardeningResult) -> int:
    score = 0
    if result.pie:
        score += 1
    if result.nx:
        score += 1
    if result.canary:
        score += 1
    if result.relro == "Full":
        score += 1
    elif result.relro == "Partial":
        score += 1
    return score


def _score_cell(result: HardeningResult) -> str:
    s = _score(result)
    if s == 4:
        return "[bold green]4/4[/bold green]"
    if s >= 2:
        return f"[yellow]{s}/4[/yellow]"
    return f"[bold red]{s}/4[/bold red]"


# ── Output renderers ──────────────────────────────────────────────────────────

def render_table(results: list[HardeningResult]) -> None:
    table = Table(
        title="ELF Hardening Report",
        box=box.ROUNDED,
        show_lines=True,
        highlight=True,
    )
    table.add_column("Binary", style="cyan", no_wrap=True)
    table.add_column("PIE", justify="center")
    table.add_column("NX", justify="center")
    table.add_column("Canary", justify="center")
    table.add_column("RELRO", justify="center")
    table.add_column("Score", justify="center")

    for r in results:
        if not r.is_elf:
            note = f"[dim]not an ELF{', ' + r.error if r.error else ''}[/dim]"
            table.add_row(r.path, note, "", "", "", "")
            continue
        if r.error:
            table.add_row(r.path, f"[red]error: {r.error}[/red]", "", "", "", "")
            continue
        table.add_row(
            r.path,
            _bool_cell(r.pie),
            _bool_cell(r.nx),
            _bool_cell(r.canary),
            _relro_cell(r.relro),
            _score_cell(r),
        )

    console.print(table)
    _print_legend()


def _print_legend() -> None:
    console.print(
        "\n[dim]PIE[/dim]    Position-Independent Executable, ASLR-compatible\n"
        "[dim]NX[/dim]     Non-Executable stack, prevents shellcode on stack\n"
        "[dim]Canary[/dim] Stack canary, detects stack buffer overflows\n"
        "[dim]RELRO[/dim]  Relocation Read-Only, protects GOT from overwrites\n"
    )


def render_json(results: list[HardeningResult]) -> None:
    output = []
    for r in results:
        output.append({
            "path": r.path,
            "is_elf": r.is_elf,
            "pie": r.pie,
            "nx": r.nx,
            "canary": r.canary,
            "relro": r.relro,
            "score": _score(r) if r.is_elf and not r.error else None,
            "error": r.error,
        })
    print(json.dumps(output, indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hardening-check",
        description=(
            "Analyze ELF binaries for common security hardening properties:\n"
            "  PIE, NX (non-executable stack), stack canary, RELRO."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "binaries",
        nargs="+",
        metavar="BINARY",
        help="One or more ELF binary paths to analyze.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output results as JSON instead of a table.",
    )
    parser.add_argument(
        "--fail-under",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Exit 1 if any binary scores below N out of 4. "
            "Use this to gate a CI pipeline on hardening coverage."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    paths = [Path(b) for b in args.binaries]
    results = analyze_many(paths)

    if args.json_output:
        render_json(results)
    else:
        render_table(results)

    # Exit non-zero if any binary had an error
    if any(r.error for r in results):
        sys.exit(1)

    # Policy gate: only meaningful for files that actually parsed as ELF.
    if args.fail_under is not None:
        failing = [
            r for r in results if r.is_elf and _score(r) < args.fail_under
        ]
        if failing:
            for r in failing:
                print(
                    f"FAIL {r.path}: score {_score(r)}/4 "
                    f"(threshold {args.fail_under})",
                    file=sys.stderr,
                )
            sys.exit(1)


if __name__ == "__main__":
    main()

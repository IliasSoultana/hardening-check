# hardening-check

A CLI tool that parses ELF binaries and reports four common security hardening properties.

## What it checks

| Property | What it means |
|---|---|
| **PIE** | Binary compiled as Position-Independent Executable — enables ASLR |
| **NX** | Non-Executable stack — prevents shellcode from running on the stack |
| **Canary** | Stack canary present — detects stack buffer overflows at runtime |
| **RELRO** | Relocation Read-Only (`None` / `Partial` / `Full`) — protects the GOT from overwrites |

## Installation

Requires Python 3.11+ and [`uv`](https://github.com/astral-sh/uv).

```bash
cd hardening-check
uv sync
```

## Usage

```bash
# Analyze one or more binaries (pretty table)
uv run hardening-check /usr/bin/ls /usr/bin/ssh /usr/bin/python3

# Machine-readable JSON output
uv run hardening-check --json /usr/bin/ls

# Direct module invocation
uv run python -m hardening_check.cli /usr/bin/ls
```

### Example output

```
╭──────────────────────────────────────────────────────╮
│               ELF Hardening Report                   │
├──────────────────┬─────┬─────┬────────┬─────────┬───╮
│ Binary           │ PIE │ NX  │ Canary │ RELRO   │ S │
├──────────────────┼─────┼─────┼────────┼─────────┼───┤
│ /usr/bin/ls      │ YES │ YES │ YES    │ Full    │ 4 │
│ /usr/bin/ssh     │ YES │ YES │ YES    │ Partial │ 3 │
╰──────────────────┴─────┴─────┴────────┴─────────┴───╯
```

## Running tests

```bash
uv run pytest tests/ -v
```

## How it works

The tool uses [`pyelftools`](https://github.com/eliben/pyelftools) to parse ELF headers and sections directly — no external tools like `checksec` or `readelf` required.

| Check | Detection method |
|---|---|
| PIE | `e_type == ET_DYN` in the ELF header |
| NX | `PT_GNU_STACK` segment: execute flag (`PF_X`) absent |
| Canary | `__stack_chk_fail` symbol in `.dynsym` |
| RELRO | `PT_GNU_RELRO` segment (Partial) + `DT_BIND_NOW` / `DF_BIND_NOW` flag (Full) |

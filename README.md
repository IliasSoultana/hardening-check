# hardening-check

[![CI](https://github.com/IliasSoultana/hardening-check/actions/workflows/ci.yml/badge.svg)](https://github.com/IliasSoultana/hardening-check/actions/workflows/ci.yml)

Parses ELF binaries and reports which exploit mitigations they were actually
compiled with — PIE, NX, stack canary and RELRO — as a table for humans or as
JSON for a pipeline.

## Why this exists

Given an unknown binary, the first useful question is not *what does it do* but
*what protects it*. The four properties below decide whether a memory-safety
bug is an inconvenience or an exploit:

| Property | What it means | What its absence buys an attacker |
|---|---|---|
| **PIE** | Position-independent executable | Fixed load address, so gadget addresses are known without an info leak |
| **NX** | Non-executable stack | Shellcode can be placed and executed on the stack directly |
| **Canary** | Stack canary (`__stack_chk_fail`) | A linear stack overflow reaches the saved return address unnoticed |
| **RELRO** | Relocation read-only | A writable GOT turns one arbitrary write into control-flow hijack |

Build systems drift. A flag gets dropped from one target, a vendored
dependency ships prebuilt, a release path differs from the debug path — and
nothing fails, because a missing mitigation is silent. This makes it loud.

## Install

Requires Python 3.11+ and [`uv`](https://github.com/astral-sh/uv).

```bash
git clone https://github.com/IliasSoultana/hardening-check
cd hardening-check
uv sync
```

## Usage

```bash
# Human-readable table
uv run hardening-check /usr/bin/ls /usr/bin/ssh

# Machine-readable, for anything downstream
uv run hardening-check --json /usr/bin/ls

# Fail the build if any binary scores below 4 out of 4
uv run hardening-check --fail-under 4 build/myapp
```

```
                ELF Hardening Report
╭───────────────┬─────┬─────┬────────┬─────────┬───────╮
│ Binary        │ PIE │ NX  │ Canary │ RELRO   │ Score │
├───────────────┼─────┼─────┼────────┼─────────┼───────┤
│ /usr/bin/ls   │ YES │ YES │  YES   │ Full    │  4/4  │
│ /usr/bin/ssh  │ YES │ YES │  YES   │ Partial │  3/4  │
╰───────────────┴─────┴─────┴────────┴─────────┴───────╯
```

### In CI

`--fail-under` is the whole point of the JSON mode having a sibling. It exits
non-zero when any ELF scores below the threshold, so a regression in build
flags stops the pipeline instead of shipping:

```yaml
- name: Hardening gate
  run: uv run hardening-check --fail-under 4 dist/*.so dist/myapp
```

Exit codes: `0` pass, `1` a binary failed the threshold or could not be read.
Non-ELF files are reported but never trip the gate, so pointing it at a mixed
build directory is safe.

The JSON is a flat array, one object per input, stable enough to diff between
builds:

```json
[
  {
    "path": "build/myapp",
    "is_elf": true,
    "pie": true,
    "nx": true,
    "canary": false,
    "relro": "Partial",
    "score": 3,
    "error": null
  }
]
```

## How it works

Everything is read straight from the ELF structure with
[`pyelftools`](https://github.com/eliben/pyelftools) — no `checksec`, no
`readelf`, no shelling out.

| Check | Detection method |
|---|---|
| PIE | `e_type == ET_DYN` in the ELF header |
| NX | `PT_GNU_STACK` segment present without the `PF_X` bit |
| Canary | `__stack_chk_fail` in `.dynsym` |
| RELRO | `PT_GNU_RELRO` segment (Partial), plus `DT_BIND_NOW` / `DF_BIND_NOW` (Full) |

## Limitations

Worth knowing before trusting the output:

- **Presence, not correctness.** A canary symbol proves the compiler emitted
  the machinery, not that every function is protected. `-fstack-protector`
  instruments far fewer functions than `-fstack-protector-strong`, and both
  report identically here. The
  [LLVM pass](https://github.com/IliasSoultana/llvm-hardeningpass) exists to
  answer that question per function, at IR level.
- **A missing `PT_GNU_STACK` reads as NX disabled.** In reality the kernel
  default then applies, which on modern Linux is non-executable. The file
  alone cannot distinguish "explicitly executable" from "unspecified", and
  this implementation resolves the ambiguity pessimistically.
- **Static binaries hide their canary.** The check reads `.dynsym`, so a
  statically linked binary with a canary can report `NO`.
- **Not a security verdict.** The score counts mitigations; it says nothing
  about whether the code has bugs worth mitigating. Four out of four is a
  floor, not an assurance.
- **ELF only.** Mach-O and PE are out of scope.

## Tests

```bash
uv run pytest -q
```

Unit tests build synthetic ELF headers in memory with a small `ELFBuilder`, so
each check is exercised against known-good byte layouts without committing
fixture binaries. CI additionally scans the runner's real system binaries and
verifies the gate on a deliberately weak binary — fixtures agree with the
parser too easily.

## Related

Same question, asked three more ways:

- [elfharden](https://github.com/IliasSoultana/elfharden) — Go, `debug/elf`
- [elfharden-rs](https://github.com/IliasSoultana/elfharden-rs) — Rust, `goblin`
- [llvm-hardeningpass](https://github.com/IliasSoultana/llvm-hardeningpass) — before linking, at IR level

The three scanners are cross-checked against the same binaries and agree.

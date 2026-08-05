"""ELF binary hardening checker — PIE, NX, stack canary, RELRO."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from elftools.elf.elffile import ELFFile


@dataclass
class HardeningResult:
    """Hardening properties found in a single ELF binary."""

    path: str
    is_elf: bool
    pie: bool | None = None
    nx: bool | None = None
    canary: bool | None = None
    relro: str | None = None  # "None" | "Partial" | "Full"
    error: str | None = None


def _check_pie(elf: ELFFile) -> bool:
    return elf.header.e_type == "ET_DYN"


def _check_nx(elf: ELFFile) -> bool:
    for segment in elf.iter_segments():
        if segment.header.p_type == "PT_GNU_STACK":
            return not bool(segment.header.p_flags & 0x1)  # PF_X
    return False


def _check_canary(elf: ELFFile) -> bool:
    dynsym = elf.get_section_by_name(".dynsym")
    if dynsym is None:
        return False
    return any(sym.name == "__stack_chk_fail" for sym in dynsym.iter_symbols())


def _check_relro(elf: ELFFile) -> str:
    has_relro_segment = any(
        seg.header.p_type == "PT_GNU_RELRO" for seg in elf.iter_segments()
    )
    if not has_relro_segment:
        return "None"

    bind_now = False
    dynamic = elf.get_section_by_name(".dynamic")
    if dynamic:
        for tag in dynamic.iter_tags():
            if tag.entry.d_tag == "DT_BIND_NOW":
                bind_now = True
                break
            if tag.entry.d_tag == "DT_FLAGS":
                if tag.entry.d_val & 0x8:  # DF_BIND_NOW
                    bind_now = True
                    break

    return "Full" if bind_now else "Partial"


def analyze(path: str | Path) -> HardeningResult:
    p = Path(path)
    result = HardeningResult(path=str(p), is_elf=False)

    try:
        with p.open("rb") as f:
            magic = f.read(4)
            if magic != b"\x7fELF":
                return result
            f.seek(0)

            result.is_elf = True
            elf = ELFFile(f)
            result.pie = _check_pie(elf)
            result.nx = _check_nx(elf)
            result.canary = _check_canary(elf)
            result.relro = _check_relro(elf)

    except FileNotFoundError:
        result.error = "file not found"
    except PermissionError:
        result.error = "permission denied"
    except Exception as exc:  # noqa: BLE001
        result.error = f"parse error: {exc}"

    return result


def analyze_many(paths: list[str | Path]) -> list[HardeningResult]:
    return [analyze(p) for p in paths]

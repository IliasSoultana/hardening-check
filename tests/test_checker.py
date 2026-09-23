"""Tests for hardening_check.checker."""

from __future__ import annotations

import struct
from io import BytesIO
from unittest.mock import patch

import pytest

from hardening_check.checker import (
    HardeningResult,
    _check_canary,
    _check_nx,
    _check_pie,
    _check_relro,
    analyze,
)


class ELFBuilder:

    EI_NIDENT = 16
    EHDR_SIZE = 64
    PHDR_SIZE = 56
    SHDR_SIZE = 64

    def __init__(self, *, pie: bool = True):
        self.e_type = 3 if pie else 2  # ET_DYN=3, ET_EXEC=2
        self.segments: list[dict] = []
        self.dynsyms: list[str] = []
        self.dynamic_tags: list[tuple[int, int]] = []

    def add_gnu_stack(self, *, executable: bool = False) -> "ELFBuilder":
        flags = 0x6  # PF_R | PF_W
        if executable:
            flags |= 0x1  # PF_X
        self.segments.append({"p_type": 0x6474E551, "p_flags": flags})  # PT_GNU_STACK
        return self

    def add_interp(self) -> "ELFBuilder":
        self.segments.append({"p_type": 0x3, "p_flags": 0x4})  # PT_INTERP
        return self

    def add_gnu_relro(self) -> "ELFBuilder":
        self.segments.append({"p_type": 0x6474E552, "p_flags": 0x4})  # PT_GNU_RELRO
        return self

    def add_canary_symbol(self) -> "ELFBuilder":
        self.dynsyms.append("__stack_chk_fail")
        return self

    def add_bind_now(self) -> "ELFBuilder":
        self.dynamic_tags.append((24, 0))  # DT_BIND_NOW = 24
        return self

    def build(self) -> BytesIO:
        e_ident = (
            b"\x7fELF"       # magic
            + b"\x02"        # EI_CLASS = ELFCLASS64
            + b"\x01"        # EI_DATA  = ELFDATA2LSB
            + b"\x01"        # EI_VERSION
            + b"\x00" * 9    # padding
        )
        ph_count = len(self.segments)
        sh_count = 0
        ph_offset = self.EHDR_SIZE

        ehdr = struct.pack(
            "<16sHHIQQQIHHHHHH",
            e_ident,
            self.e_type,          # e_type
            0x3E,                 # e_machine = EM_X86_64
            1,                    # e_version
            0,                    # e_entry
            ph_offset,            # e_phoff
            0,                    # e_shoff
            0,                    # e_flags
            self.EHDR_SIZE,       # e_ehsize
            self.PHDR_SIZE,       # e_phentsize
            ph_count,             # e_phnum
            self.SHDR_SIZE,       # e_shentsize
            sh_count,             # e_shnum
            0,                    # e_shstrndx
        )

        phdrs = b""
        for seg in self.segments:
            phdrs += struct.pack(
                "<IIQQQQQQ",
                seg["p_type"],
                seg["p_flags"],
                0,   # p_offset
                0,   # p_vaddr
                0,   # p_paddr
                0,   # p_filesz
                0,   # p_memsz
                0,   # p_align
            )

        return BytesIO(ehdr + phdrs)


def _elf(builder: ELFBuilder):
    from elftools.elf.elffile import ELFFile
    return ELFFile(builder.build())


def test_pie_detected():
    """ET_DYN plus PT_INTERP is a PIE."""
    elf = _elf(ELFBuilder(pie=True).add_interp())
    assert _check_pie(elf) is True


def test_shared_library_is_not_pie():
    """ET_DYN with neither DF_1_PIE nor PT_INTERP is a plain shared object."""
    elf = _elf(ELFBuilder(pie=True))
    assert _check_pie(elf) is False


def test_no_pie_detected():
    elf = _elf(ELFBuilder(pie=False))
    assert _check_pie(elf) is False


def test_nx_enabled():
    elf = _elf(ELFBuilder().add_gnu_stack(executable=False))
    assert _check_nx(elf) is True


def test_nx_disabled():
    elf = _elf(ELFBuilder().add_gnu_stack(executable=True))
    assert _check_nx(elf) is False


def test_nx_no_segment_is_unknown():
    """No PT_GNU_STACK means the kernel default applies -- not that NX is off."""
    elf = _elf(ELFBuilder())  # no GNU_STACK segment
    assert _check_nx(elf) is None


def test_relro_none():
    elf = _elf(ELFBuilder())  # no GNU_RELRO segment
    assert _check_relro(elf) == "None"


def test_relro_partial():
    elf = _elf(ELFBuilder().add_gnu_relro())
    assert _check_relro(elf) == "Partial"


def test_analyze_nonexistent_file():
    result = analyze("/nonexistent/path/to/binary")
    assert result.is_elf is False
    assert result.error == "file not found"


def test_analyze_non_elf_file(tmp_path):
    f = tmp_path / "script.sh"
    f.write_bytes(b"#!/bin/bash\necho hello\n")
    result = analyze(f)
    assert result.is_elf is False
    assert result.error is None


def test_analyze_returns_hardening_result(tmp_path):
    f = tmp_path / "fake.elf"
    # Build a minimal PIE + NX + canary + partial RELRO binary
    builder = (
        ELFBuilder(pie=True)
        .add_interp()
        .add_gnu_stack(executable=False)
        .add_gnu_relro()
    )
    f.write_bytes(builder.build().read())

    # Patch _check_canary to avoid needing a real .dynsym section
    with patch("hardening_check.checker._check_canary", return_value=True):
        result = analyze(f)

    assert isinstance(result, HardeningResult)
    assert result.is_elf is True
    assert result.pie is True
    assert result.nx is True
    assert result.canary is True
    assert result.relro == "Partial"
    assert result.error is None

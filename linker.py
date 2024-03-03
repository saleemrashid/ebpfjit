import enum
from typing import Iterator, NamedTuple, Optional, Self

from bitstring import ConstBitStream
from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import Relocation, RelocationSection
from elftools.elf.sections import Section as ELFSection
from elftools.elf.sections import Symbol as ELFSymbol
from elftools.elf.sections import SymbolTableSection

import bpf
import disasm

BPF_INSTRUCTION_SIZE = 8


class RelocationType(enum.IntEnum):
    R_BPF_64_64 = 1
    R_BPF_64_32 = 10


class SectionId(enum.Enum):
    Text = enum.auto()
    Rodata = enum.auto()
    Data = enum.auto()


class SymbolId(NamedTuple):
    name: str
    section: bool
    file_idx: Optional[int] = None

    @classmethod
    def for_section(cls, name: str, file_idx: int) -> Self:
        return cls(name, True, file_idx)


class Symbol(NamedTuple):
    section: SectionId
    start: int
    end: int


class Linker(object):
    def __init__(self) -> None:
        self.file_idx = 0
        self.sections: dict[SectionId, bytearray] = {
            section_id: bytearray() for section_id in SectionId
        }

        self.symbols: dict[SymbolId, Symbol] = {}
        self.symbol_aliases: dict[SymbolId, SymbolId] = {}
        self.symbol_addrs: dict[SectionId, dict[int, SymbolId]] = {
            section_id: {} for section_id in SectionId
        }

        self.program: list[bpf.Instruction] = []

    def _add_symbol(self, symbol_id: SymbolId, symbol: Symbol):
        section_addrs = self.symbol_addrs[symbol.section]

        if existing := section_addrs.get(symbol.start):
            # FIXME(saleem): no two symbols should have the same address? but __rdl_oom and memmove did
            self.symbol_aliases[symbol_id] = existing
        else:
            self.symbols[symbol_id] = symbol
            self.symbol_aliases[symbol_id] = symbol_id
            section_addrs[symbol.start] = symbol_id

    def _resolve_symbol(self, symbol_id: SymbolId, offset: int) -> tuple[SymbolId, int]:
        # TODO(saleem): handle extern better?
        if symbol_id not in self.symbol_aliases:
            return symbol_id, offset

        symbol = self.symbols.get(self.symbol_aliases[symbol_id])
        section_addrs = self.symbol_addrs[symbol.section]

        if resolved := section_addrs.get(symbol.start + offset):
            return resolved, 0
        elif symbol.section == SectionId.Text:
            raise ValueError(f"cannot offset symbol {symbol_id!r} in .text section")
        else:
            return section_addrs[symbol.start], offset

    @staticmethod
    def _iter_symbols(elf: ELFFile, idx: int) -> Iterator[ELFSymbol]:
        for symbol_table in elf.iter_sections():
            if not isinstance(symbol_table, SymbolTableSection):
                continue

            for symbol in symbol_table.iter_symbols():
                if symbol["st_shndx"] != idx:
                    continue

                yield symbol

    @staticmethod
    def _get_symtab(elf: ELFFile) -> SymbolTableSection:
        sections = [
            section
            for section in elf.iter_sections()
            if isinstance(section, SymbolTableSection)
        ]
        if len(sections) != 1:
            raise ValueError("expected one symbol table")

        return sections[0]

    @staticmethod
    def _iter_relocations(
        elf: ELFFile, idx: int
    ) -> Iterator[tuple[SymbolTableSection, Relocation]]:
        for reloc_section in elf.iter_sections():
            if not isinstance(reloc_section, RelocationSection):
                continue
            if reloc_section["sh_info"] != idx:
                continue

            symbol_table = elf.get_section(reloc_section["sh_link"])
            for reloc in reloc_section.iter_relocations():
                yield symbol_table, reloc

    @staticmethod
    def _section_id(section: ELFSection) -> Optional[SectionId]:
        sh_flags = section["sh_flags"]

        if not sh_flags & SH_FLAGS.SHF_ALLOC:
            return None

        if sh_flags & SH_FLAGS.SHF_EXECINSTR:
            return SectionId.Text
        elif sh_flags & SH_FLAGS.SHF_WRITE:
            return SectionId.Data
        else:
            return SectionId.Rodata

    @staticmethod
    def _symbol_id(
        file_idx: int, elf: ELFFile, symbol: ELFSymbol
    ) -> Optional[SymbolId]:
        st_bind = symbol["st_info"]["bind"]
        st_type = symbol["st_info"]["type"]

        if st_bind == "STB_LOCAL":
            local = True
        elif st_bind in ("STB_GLOBAL", "STB_WEAK"):
            # TODO(saleem): handle weak symbols correctly
            local = False
        else:
            raise NotImplementedError(f"symbol bind {st_bind!r}")

        if local and st_type == "STT_NOTYPE":
            return None
        elif st_type == "STT_SECTION":
            name = elf.get_section(symbol["st_shndx"]).name
            section = True
        elif st_type in (
            "STT_NOTYPE",
            "STT_FUNC",
            "STT_OBJECT",
        ):
            name = symbol.name
            section = False
        else:
            raise NotImplementedError(f"symbol type {st_type!r}")

        if local:
            return SymbolId(name, section, file_idx)
        else:
            return SymbolId(name, section)

    def _add_elf_section(
        self, file_idx: int, section_id: SectionId, elf: ELFFile, idx: int
    ) -> None:
        elf_section = elf.get_section(idx)

        if elf_section["sh_type"] == "SHT_PROGBITS":
            data = elf_section.data()
        else:
            data = bytes(elf_section["sh_size"])

        raw_section = self.sections[section_id]

        base_addr = len(raw_section)
        raw_section.extend(data)

        for symbol in self._iter_symbols(elf, idx):
            symbol_id = self._symbol_id(file_idx, elf, symbol)
            if symbol_id is None or symbol_id.section:
                continue

            start = base_addr + symbol["st_value"]
            end = start + symbol["st_size"]
            self._add_symbol(symbol_id, Symbol(section_id, start, end))

        self._add_symbol(
            SymbolId.for_section(elf_section.name, file_idx),
            Symbol(section_id, base_addr, base_addr + len(data)),
        )

    def _add_elf_relocs(
        self, file_idx: int, section_id: SectionId, elf: ELFFile, idx: int
    ) -> None:
        if section_id != SectionId.Text:
            return

        elf_section = elf.get_section(idx)

        func_addrs = self.symbol_addrs[SectionId.Text]
        base_symbol_id = SymbolId.for_section(elf_section.name, file_idx)

        program = disasm.disasm(ConstBitStream(bytes=elf_section.data()))

        for symbol_table, reloc in self._iter_relocations(elf, idx):
            elf_symbol = symbol_table.get_symbol(reloc["r_info_sym"])
            symbol_id = self._symbol_id(file_idx, elf, elf_symbol)

            if symbol_id is None:
                raise ValueError(f"invalid relocation for symbol {elf_symbol.name!r}")

            pc = reloc["r_offset"] // BPF_INSTRUCTION_SIZE
            ins = program[pc]

            reloc_type = RelocationType(reloc["r_info_type"])
            match reloc_type:
                case RelocationType.R_BPF_64_64:
                    if not isinstance(ins, bpf.LoadImm64):
                        raise ValueError(f"{reloc_type.name} requires BPF_LD imm64")

                    resolved, offset = self._resolve_symbol(symbol_id, ins.imm64)
                    program[pc] = ins._replace(
                        imm32=(offset & 0xFFFFFFFF),
                        next_imm=(offset >> 32),
                        addr=resolved,
                    )

                case RelocationType.R_BPF_64_32:
                    if (
                        not isinstance(ins, bpf.Jump)
                        or ins.opcode.code != bpf.JumpCode.CALL
                    ):
                        raise ValueError(f"{reloc_type.name} requires BPF_CALL")

                    # TODO(saleem): should there be an offset?
                    resolved, _ = self._resolve_symbol(symbol_id, 0)
                    # assert self.symbols[resolved].section == SectionId.Text

                    program[pc] = ins._replace(symbol=resolved)

                case _:
                    raise NotImplementedError(f"{reloc_type.name} not supported")

        for pc, ins in enumerate(program):
            match ins:
                case bpf.Jump(
                    opcode=bpf.JumpOpcode(code=bpf.JumpCode.CALL, source=bpf.Source.K)
                ):
                    if ins.symbol is not None:
                        continue

                    resolved, _ = self._resolve_symbol(
                        base_symbol_id, (pc + 1 + ins.imm) * BPF_INSTRUCTION_SIZE
                    )
                    program[pc] = ins._replace(symbol=resolved)

        self.program.extend(program)

    def add_elf(self, elf: ELFFile) -> None:
        file_idx = self.file_idx
        self.file_idx += 1

        for idx, section in enumerate(elf.iter_sections()):
            section_id = self._section_id(section)
            if section_id is not None:
                self._add_elf_section(file_idx, section_id, elf, idx)

        for idx, section in enumerate(elf.iter_sections()):
            section_id = self._section_id(section)
            if section_id is not None:
                self._add_elf_relocs(file_idx, section_id, elf, idx)


if __name__ == "__main__":
    import sys

    (filename,) = sys.argv[1:]

    linker = Linker()
    with open(filename, "rb") as f:
        linker.add_elf(ELFFile(f))

    import pprint

    pprint.pp(linker.program)

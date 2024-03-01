import enum
from typing import Iterator, NamedTuple, Optional

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
        self.addrs: dict[SectionId, dict[int, SymbolId]] = {
            section_id: {} for section_id in SectionId
        }
        self.symbols: dict[SymbolId, Symbol] = {}
        self.program: list[bpf.Instruction] = []

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
            raise NotImplementedError(f".data section ({section.name!r})")
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
        elif st_bind == "STB_GLOBAL":
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
        data = elf_section.data()

        raw_section = self.sections[section_id]
        addrs = self.addrs[section_id]

        addr_offset = len(raw_section)
        raw_section.extend(data)

        for symbol in self._iter_symbols(elf, idx):
            symbol_id = self._symbol_id(file_idx, elf, symbol)
            if symbol_id is None:
                continue

            value = symbol["st_value"]
            size = symbol["st_size"]

            start = addr_offset + value
            end = start + size

            # TODO(saleem): check uniqueness
            self.symbols[symbol_id] = Symbol(section_id, start, end)
            if not symbol_id.section:
                addrs[start] = symbol_id

        self.symbols[SymbolId(elf_section.name, True, file_idx)] = Symbol(
            section_id, addr_offset, addr_offset + len(data)
        )

    def _add_elf_relocs(
        self, file_idx: int, section_id: SectionId, elf: ELFFile, idx: int
    ) -> None:
        if section_id != SectionId.Text:
            return

        elf_section = elf.get_section(idx)

        func_addrs = self.addrs[SectionId.Text]
        addr_offset = self.symbols[SymbolId(elf_section.name, True, file_idx)].start

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

                    try:
                        base_symbol = self.symbols[symbol_id]
                    except KeyError:
                        pass
                    else:
                        if base_symbol.section == SectionId.Text:
                            symbol_id = func_addrs[base_symbol.start + ins.imm64]
                            ins = ins._replace(imm32=0, next_imm=0)

                    program[pc] = ins._replace(addr=symbol_id)

                case RelocationType.R_BPF_64_32:
                    if (
                        not isinstance(ins, bpf.Jump)
                        or ins.opcode.code != bpf.JumpCode.CALL
                    ):
                        raise ValueError(f"{reloc_type.name} requires BPF_CALL")

                    program[pc] = ins._replace(symbol=symbol_id)

                case _:
                    raise NotImplementedError(f"{reloc_type.name} not supported")

        for pc, ins in enumerate(program):
            match ins:
                case bpf.Jump(
                    opcode=bpf.JumpOpcode(code=bpf.JumpCode.CALL, source=bpf.Source.K)
                ):
                    if ins.symbol is not None:
                        continue

                    addr = addr_offset + (pc + 1 + ins.imm) * BPF_INSTRUCTION_SIZE
                    program[pc] = ins._replace(symbol=func_addrs[addr])

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

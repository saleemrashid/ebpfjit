import enum
from typing import Iterator, NamedTuple

from bitstring import ConstBitStream
from elftools.elf.constants import SH_FLAGS  # type: ignore
from elftools.elf.elffile import ELFFile  # type: ignore
from elftools.elf.relocation import Relocation, RelocationSection  # type: ignore
from elftools.elf.sections import Symbol, SymbolTableSection  # type: ignore

import bpf
import disasm

BPF_INSTRUCTION_SIZE = 8


class RelocationType(enum.IntEnum):
    R_BPF_64_64 = 1
    R_BPF_64_32 = 10


class Function(NamedTuple):
    start: int
    end: int


class Linker(object):
    def __init__(self) -> None:
        self.text: list[bpf.Instruction] = []
        self.rodata = bytearray()
        self.functions: dict[str, Function] = {}

    @staticmethod
    def _iter_symbols(elf: ELFFile, idx: int) -> Iterator[Symbol]:
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

    def add_elf(self, elf: ELFFile) -> None:
        for idx, section in enumerate(elf.iter_sections()):
            sh_flags = section["sh_flags"]

            if not sh_flags & SH_FLAGS.SHF_ALLOC:
                continue

            # .text
            if sh_flags & SH_FLAGS.SHF_EXECINSTR:
                program = disasm.disasm(ConstBitStream(bytes=section.data()))

                for symbol_table, reloc in self._iter_relocations(elf, idx):
                    offset = reloc["r_offset"] // BPF_INSTRUCTION_SIZE
                    ins = program[offset]
                    reloc_type = RelocationType(reloc["r_info_type"])
                    symbol = symbol_table.get_symbol(reloc["r_info_sym"])

                    match reloc_type:
                        case RelocationType.R_BPF_64_64:
                            if not isinstance(ins, bpf.LoadImm64):
                                raise ValueError(
                                    f"{reloc_type.name} requires BPF_LD imm64"
                                )

                            program[offset] = ins._replace(
                                addr=len(self.text) + ins.imm64 // BPF_INSTRUCTION_SIZE
                            )

                        case RelocationType.R_BPF_64_32:
                            if (
                                not isinstance(ins, bpf.Jump)
                                or ins.opcode.code != bpf.JumpCode.CALL
                            ):
                                raise ValueError(f"{reloc_type.name} requires BPF_CALL")

                            program[offset] = ins._replace(symbol=symbol.name)
                        case _:
                            raise NotImplementedError(
                                f"{reloc_type.name} not supported"
                            )

                for symbol in self._iter_symbols(elf, idx):
                    st_type = symbol["st_info"]["type"]
                    if st_type != "STT_FUNC":
                        continue

                    start = symbol["st_value"] // BPF_INSTRUCTION_SIZE
                    size = symbol["st_size"] // BPF_INSTRUCTION_SIZE
                    self.functions[symbol.name] = Function(
                        len(self.text) + start, len(self.text) + start + size
                    )

                self.text.extend(program)
            # .data
            elif sh_flags & SH_FLAGS.SHF_WRITE:
                raise NotImplementedError(".data section")
            # .rodata
            else:
                # raise NotImplementedError(".rodata section")
                pass


if __name__ == "__main__":
    import sys

    (filename,) = sys.argv[1:]

    linker = Linker()
    with open(filename, "rb") as f:
        linker.add_elf(ELFFile(f))
    print(linker.functions)

import pprint
from typing import Iterator

from bitstring import ConstBitStream

import bpf


def iter_disasm_one(s: ConstBitStream) -> Iterator[bpf.Instruction]:
    ins_fields = s.read(5)
    ins_class = bpf.InsClass(s.read("u3"))
    src_reg = s.read("u4")
    dst_reg = bpf.Reg(s.read("u4"))
    offset = s.read("intle16")
    imm = s.read("intle32")

    opcode: bpf.Opcode
    if ins_class.is_alu():
        opcode = bpf.AluOpcode(
            bpf.AluCode(ins_fields.read("u4")),
            bpf.Source(ins_fields.read("u1")),
            ins_class,
        )
        yield bpf.Alu(opcode, bpf.Reg(src_reg), dst_reg, offset, imm)
    elif ins_class.is_jump():
        opcode = bpf.JumpOpcode(
            bpf.JumpCode(ins_fields.read("u4")),
            bpf.Source(ins_fields.read("u1")),
            ins_class,
        )
        yield bpf.Jump(opcode, bpf.Reg(src_reg), dst_reg, offset, imm)
    elif ins_class.is_load() or ins_class.is_store():
        opcode = bpf.LoadStoreOpcode(
            bpf.Mode(ins_fields.read("u3")), bpf.Size(ins_fields.read("u2")), ins_class
        )

        if ins_class == bpf.InsClass.LD:
            if opcode.mode != bpf.Mode.IMM or opcode.size != bpf.Size.DW:
                raise ValueError(
                    f"{bpf.InsClass.LD.name} requires {bpf.Mode.IMM.name} | {bpf.Size.DW.name}"
                )

            unused = s.read(32)
            if unused.uint != 0:
                raise ValueError(
                    f"pseudo-instruction was 0x{unused.hex}, expected zeroes"
                )
            next_imm = s.read("intle32")

            yield bpf.LoadImm64(
                opcode, bpf.LoadSource(src_reg), dst_reg, offset, imm, next_imm
            )
            yield None
        else:
            if opcode.mode == bpf.Mode.IMM:
                raise ValueError(
                    f"{bpf.Mode.IMM.name} only allowed for {bpf.InsClass.LD.name} instruction"
                )

            yield bpf.LoadStore(opcode, bpf.Reg(src_reg), dst_reg, offset, imm)
    else:
        raise NotImplementedError(f"{ins_class.name}")


def iter_disasm(stream: ConstBitStream) -> Iterator[bpf.Instruction]:
    while stream.bitpos < len(stream):
        yield from iter_disasm_one(stream)


def disasm(stream: ConstBitStream) -> list[bpf.Instruction]:
    return list(iter_disasm(stream))


if __name__ == "__main__":
    stream = ConstBitStream(filename="samples/hello.bin")
    pprint.pprint(list(iter_disasm(stream)))

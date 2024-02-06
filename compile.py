from bitstring import ConstBitStream
from llvmlite import ir  # type: ignore

import bpf
import disasm
from typing import Iterator

I32 = ir.IntType(32)
I64 = ir.IntType(64)


class Compiler(object):
    def __init__(self, program: list[bpf.Instruction]):
        self.program = program

    def _append_block(self) -> ir.IRBuilder:
        return ir.IRBuilder(self.main_func.append_basic_block())

    def compile(self) -> ir.Module:
        self.module = ir.Module()
        self.main_func = ir.Function(
            self.module, ir.FunctionType(I64, (I64,)), "bpf_main"
        )

        builder = self._append_block()

        # Prelude
        self.registers = self._alloc_reg(builder)
        self._store_reg(builder, bpf.Reg.R1, self.main_func.args[0])

        self._compile(builder, iter(self.program))

        return self.module

    @staticmethod
    def _alloc_reg(builder: ir.IRBuilder) -> dict[bpf.Reg, ir.AllocaInstr]:
        return {
            register: builder.alloca(I64, name=register.name) for register in bpf.Reg
        }

    def _load_reg(self, builder: ir.IRBuilder, reg: bpf.Reg, alu64: bool = True) -> ir.Value:
        value = builder.load(self.registers[reg])
        if not alu64:
            value = builder.trunc(value, I32)
        return value

    def _store_reg(
        self, builder: ir.IRBuilder, reg: bpf.Reg, value: ir.Value, alu64: bool = True
    ) -> None:
        if not alu64:
            value = builder.zext(value, I64)
        builder.store(value, self.registers[reg])

    def _compile(
        self, builder: ir.IRBuilder, program: Iterator[bpf.Instruction]
    ) -> None:
        for instruction in program:
            builder.comment(f"{instruction!r}")
            match instruction:
                case bpf.Alu(opcode, src_reg, dst_reg, offset, imm):
                    alu64 = opcode.ins_class == bpf.InsClass.ALU64

                    match opcode.source:
                        case bpf.Source.K:
                            if alu64:
                                # imm is int32_t, so this is sign-extension semantics
                                src = ir.Constant(I64, imm)
                            else:
                                src = ir.Constant(I32, imm)
                        case bpf.Source.X:
                            src = self._load_reg(builder, src_reg, alu64)

                    dst = self._load_reg(builder, dst_reg, alu64)

                    match opcode.code:
                        case bpf.AluCode.ADD:
                            dst = builder.add(dst, src)
                        case bpf.AluCode.MOV:
                            dst = src
                        case _:
                            raise NotImplementedError(f"{opcode!r}")

                    self._store_reg(builder, dst_reg, dst, alu64)
                case bpf.Jump(opcode):
                    match opcode.code:
                        case bpf.JumpCode.EXIT:
                            builder.ret(self._load_reg(builder, bpf.Reg.R0))
                        case _:
                            raise NotImplementedError(f"{opcode!r}")
                case _:
                    raise NotImplementedError(f"{instruction!r}")


def compile_program(instructions: list[bpf.Instruction]) -> ir.Module:
    module = ir.Module()

    func = ir.Function(module, ir.FunctionType(I64, (I64,)), name="bpf_main")

    builder = ir.IRBuilder(func.append_basic_block())
    builder.ret(ir.Constant(I64, 12345))

    return module


if __name__ == "__main__":
    stream = ConstBitStream(filename="samples/add.bin")
    program = disasm.disasm(stream)
    compiler = Compiler(program)
    print(compiler.compile())

from typing import Iterator

from bitstring import ConstBitStream
from llvmlite import ir  # type: ignore

import bpf
import disasm

I8 = ir.IntType(8)
I16 = ir.IntType(16)
I32 = ir.IntType(32)
I64 = ir.IntType(64)

BPF_SIZE_TO_TYPE = {
    bpf.Size.B: I8,
    bpf.Size.H: I16,
    bpf.Size.W: I32,
    bpf.Size.DW: I64,
}


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
        (stack_begin, stack_end) = self._alloc_stack(builder, 512)
        self.registers = self._alloc_reg(builder)

        self._store_reg(builder, bpf.Reg.R1, self.main_func.args[0])
        self._store_reg(builder, bpf.Reg.R10, builder.ptrtoint(stack_end, I64))

        self._compile(builder, iter(self.program))

        return self.module

    @staticmethod
    def _alloc_stack(builder: ir.IRBuilder, size: int) -> tuple[ir.Value, ir.Value]:
        if size % 8 != 0:
            raise ValueError("size must be a multiple of 8")
        count = size // 8

        stack_begin = builder.alloca(I64, count)
        stack_end = builder.gep(stack_begin, (I64(count),))
        return (stack_begin, stack_end)

    @staticmethod
    def _alloc_reg(builder: ir.IRBuilder) -> dict[bpf.Reg, ir.Value]:
        return {
            register: builder.alloca(I64, name=register.name) for register in bpf.Reg
        }

    def _load_reg(
        self, builder: ir.IRBuilder, reg: bpf.Reg, alu64: bool = True
    ) -> ir.Value:
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
        for ins in program:
            builder.comment(f"{ins!r}")
            match ins:
                case bpf.Alu(opcode, src_reg, dst_reg, offset, imm):
                    alu64 = opcode.ins_class == bpf.InsClass.ALU64
                    mask = I64(63) if alu64 else I32(31)

                    match opcode.source:
                        case bpf.Source.K:
                            if alu64:
                                # imm is int32_t, so this is sign-extension semantics
                                src = I64(imm)
                            else:
                                src = I32(imm)
                        case bpf.Source.X:
                            src = self._load_reg(builder, src_reg, alu64)

                    dst = self._load_reg(builder, dst_reg, alu64)

                    match opcode.code:
                        case bpf.AluCode.ADD:
                            dst = builder.add(dst, src)
                        case bpf.AluCode.MUL:
                            dst = builder.mul(dst, src)
                        case bpf.AluCode.MOV:
                            dst = src
                        case bpf.AluCode.LSH:
                            # dst <<= (src & mask)
                            dst = builder.shl(dst, builder.and_(src, mask))
                        case bpf.AluCode.ARSH:
                            # dst s>>= (src & mask)
                            dst = builder.ashr(dst, builder.and_(src, mask))
                        case _:
                            raise NotImplementedError(f"{opcode!r}")

                    self._store_reg(builder, dst_reg, dst, alu64)

                case bpf.Jump(opcode):
                    match opcode.code:
                        case bpf.JumpCode.EXIT:
                            builder.ret(self._load_reg(builder, bpf.Reg.R0))
                        case _:
                            raise NotImplementedError(f"{opcode!r}")

                case bpf.LoadImm64(opcode, src, dst_reg, offset):
                    match src:
                        case bpf.LoadSource.IMM64:
                            result = I64(ins.imm64)
                        case _:
                            raise NotImplementedError(f"{src!r}")

                    self._store_reg(builder, dst_reg, result)

                case bpf.LoadStore(opcode, src_reg, dst_reg, offset, imm):
                    size_type = BPF_SIZE_TO_TYPE[opcode.size]

                    if opcode.ins_class == bpf.InsClass.LDX:
                        # result = *(unsigned size *) (src + offset)
                        result = builder.load(
                            builder.inttoptr(
                                builder.add(
                                    self._load_reg(builder, src_reg), I64(offset)
                                ),
                                size_type.as_pointer(),
                            )
                        )

                        match opcode.mode:
                            case bpf.Mode.MEM:
                                result = builder.zext(result, I64)
                            case bpf.Mode.MEMSX:
                                result = builder.sext(result, I64)
                            case _ as mode:
                                raise ValueError(f"{mode.name} is unsupported")

                        self._store_reg(builder, dst_reg, result)
                    else:
                        if opcode.ins_class == bpf.InsClass.ST:
                            src = builder.trunc(
                                self._load_reg(builder, src_reg), size_type
                            )
                        elif opcode.ins_class == bpf.InsClass.STX:
                            src = size_type(imm)
                        else:
                            raise AssertionError(f"{ins!r}")

                        # dst_ptr = (size *) (dst + offset)
                        dst_ptr = builder.inttoptr(
                            builder.add(self._load_reg(builder, dst_reg), I64(offset)),
                            size_type.as_pointer(),
                        )
                        builder.store(src, dst_ptr)

                case _:
                    raise NotImplementedError(f"{ins!r}")


def compile_program(instructions: list[bpf.Instruction]) -> ir.Module:
    module = ir.Module()

    func = ir.Function(module, ir.FunctionType(I64, (I64,)), name="bpf_main")

    builder = ir.IRBuilder(func.append_basic_block())
    builder.ret(ir.Constant(I64, 12345))

    return module


if __name__ == "__main__":
    stream = ConstBitStream(filename="samples/hello.bin")
    program = disasm.disasm(stream)
    compiler = Compiler(program)
    print(compiler.compile())

#!/usr/bin/env python3
from typing import Iterable, Iterator, Union

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

    def compile(self) -> ir.Module:
        self.module = ir.Module()
        self.main_func = ir.Function(
            self.module, ir.FunctionType(I64, (I64,)), "bpf_main"
        )

        # Prelude
        self.builder = ir.IRBuilder(self.main_func.append_basic_block("entry"))
        (stack_begin, stack_end) = self._alloc_stack(self.builder, 512)
        self.registers = self._alloc_reg(self.builder)

        self.store_reg(bpf.Reg.R1, self.main_func.args[0])
        self.store_reg(bpf.Reg.R10, self.builder.ptrtoint(stack_end, I64))

        # Create basic blocks
        self._create_blocks()

        for pc, ins in self._enumerate(self.program):
            self._compile(pc, ins)

        return self.module

    @staticmethod
    def _enumerate(
        program: Iterable[bpf.Instruction],
    ) -> Iterator[tuple[int, bpf.Instruction]]:
        pc = 0
        for ins in program:
            yield pc, ins
            pc += ins.size

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

    def _create_block(self, pc: int):
        if pc not in self.blocks:
            self.blocks[pc] = self.builder.append_basic_block(f"L{pc}")

    def _create_blocks(self) -> dict[int, ir.Block]:
        self.blocks = {}
        needs_block = True

        for pc, ins in self._enumerate(self.program):
            if needs_block:
                self._create_block(pc)

            next_pc = pc + ins.size
            match ins:
                case bpf.Jump():
                    needs_block = True
                    if ins.jump_offset is not None:
                        self._create_block(next_pc + ins.jump_offset)
                case _:
                    needs_block = False

    def load_reg(self, reg: bpf.Reg, is_64: bool = True) -> ir.Value:
        value = self.builder.load(self.registers[reg])
        if not is_64:
            value = self.builder.trunc(value, I32)
        return value

    def load_src(self, ins: Union[bpf.Alu, bpf.Jump]) -> ir.Value:
        match ins.opcode.source:
            case bpf.Source.K:
                if ins.is_64:
                    # imm is int32_t, so this is sign-extension semantics
                    return I64(ins.imm)
                else:
                    return I32(ins.imm)
            case bpf.Source.X:
                return self.load_reg(ins.src_reg, ins.is_64)

    def store_reg(self, reg: bpf.Reg, value: ir.Value, alu64: bool = True) -> None:
        if not alu64:
            value = self.builder.zext(value, I64)
        self.builder.store(value, self.registers[reg])

    def _compile(self, pc: int, ins: bpf.Instruction) -> None:
        if block := self.blocks.get(pc):
            # XXX(saleem): we should do this in the block analysis phase?
            if not self.builder.block.is_terminated:
                self.builder.branch(block)
            self.builder.position_at_end(block)

        self.builder.comment(f"{pc=}, {ins!r}")
        match ins:
            case bpf.Alu(opcode, _, dst_reg, offset, imm):
                mask = I64(63) if ins.is_64 else I32(31)
                zero = I64(0) if ins.is_64 else I32(0)

                src = self.load_src(ins)
                dst = self.load_reg(dst_reg, ins.is_64)

                match opcode.code:
                    case bpf.AluCode.ADD:
                        # dst += src
                        dst = self.builder.add(dst, src)
                    case bpf.AluCode.MUL:
                        # dst *= src
                        dst = self.builder.mul(dst, src)
                    case bpf.AluCode.MOV:
                        dst = src
                    case bpf.AluCode.LSH:
                        # dst <<= (src & mask)
                        dst = self.builder.shl(dst, self.builder.and_(src, mask))
                    case bpf.AluCode.MOD:
                        # dst = (src != 0) ? (dst % src) : dst
                        dst = self.builder.select(
                            self.builder.icmp_unsigned("!=", src, zero),
                            self.builder.urem(dst, src),
                            dst,
                        )
                    case bpf.AluCode.ARSH:
                        # dst s>>= (src & mask)
                        dst = self.builder.ashr(dst, self.builder.and_(src, mask))
                    case _:
                        raise NotImplementedError(f"{opcode!r}")

                self.store_reg(dst_reg, dst, ins.is_64)

            case bpf.Jump(opcode, _, dst_reg, offset, imm):
                src = self.load_src(ins)
                dst = self.load_reg(dst_reg, ins.is_64)

                match opcode.code:
                    case bpf.JumpCode.EXIT:
                        self.builder.ret(self.load_reg(bpf.Reg.R0))
                    case _ as code:
                        match code:
                            case bpf.JumpCode.JEQ:
                                # PC += offset if dst == src
                                cond = self.builder.icmp_unsigned("==", dst, src)
                            case bpf.JumpCode.JLT:
                                # PC += offset if dst < src (unsigned)
                                cond = self.builder.icmp_unsigned("<", dst, src)
                            case _:
                                raise NotImplementedError(f"{opcode!r}")

                        next_pc = pc + ins.size

                        assert ins.jump_offset is not None
                        target = next_pc + ins.jump_offset

                        if cond is None:
                            self.builder.branch(self.blocks[target])
                        else:
                            self.builder.cbranch(
                                cond,
                                self.blocks[target],
                                self.blocks[next_pc],
                            )

            case bpf.LoadImm64(opcode, src, dst_reg, offset):
                match src:
                    case bpf.LoadSource.IMM64:
                        result = I64(ins.imm64)
                    case _:
                        raise NotImplementedError(f"{src!r}")

                self.store_reg(dst_reg, result)

            case bpf.LoadStore(opcode, src_reg, dst_reg, offset, imm):
                size_type = BPF_SIZE_TO_TYPE[opcode.size]

                if opcode.ins_class == bpf.InsClass.LDX:
                    # result = *(unsigned size *) (src + offset)
                    result = self.builder.load(
                        self.builder.inttoptr(
                            self.builder.add(self.load_reg(src_reg), I64(offset)),
                            size_type.as_pointer(),
                        )
                    )

                    match opcode.mode:
                        case bpf.Mode.MEM:
                            result = self.builder.zext(result, I64)
                        case bpf.Mode.MEMSX:
                            result = self.builder.sext(result, I64)
                        case _ as mode:
                            raise ValueError(f"{mode.name} is unsupported")

                    self.store_reg(dst_reg, result)
                else:
                    if opcode.ins_class == bpf.InsClass.ST:
                        src = size_type(imm)
                    elif opcode.ins_class == bpf.InsClass.STX:
                        src = self.builder.trunc(self.load_reg(src_reg), size_type)
                    else:
                        raise AssertionError(f"{ins!r}")

                    # dst_ptr = (size *) (dst + offset)
                    dst_ptr = self.builder.inttoptr(
                        self.builder.add(self.load_reg(dst_reg), I64(offset)),
                        size_type.as_pointer(),
                    )
                    self.builder.store(src, dst_ptr)

            case _:
                raise NotImplementedError(f"{ins!r}")


if __name__ == "__main__":
    import sys

    (filename,) = sys.argv[1:]

    stream = ConstBitStream(filename=filename)
    program = disasm.disasm(stream)
    compiler = Compiler(program)
    print(compiler.compile())

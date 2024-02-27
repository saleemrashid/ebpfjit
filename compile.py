#!/usr/bin/env python3
from typing import Union, Iterator

from elftools.elf.elffile import ELFFile  # type: ignore
from llvmlite import ir  # type: ignore

import bpf
from linker import Linker

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

BPF_ARGS = 5


class Compiler(object):
    def __init__(self) -> None:
        self.module = ir.Module()
        self.functions: dict[str, ir.Function] = {}
        self.blocks: dict[int, ir.Block] = {}

    @staticmethod
    def _args_regs() -> Iterator[bpf.Reg]:
        for i in range(BPF_ARGS):
            yield bpf.Reg(bpf.Reg.R1 + i)

    # TODO(saleem): Remove the var_arg parameter
    def declare_function(self, name: str, args: int = BPF_ARGS, var_arg: bool = False):
        self.functions[name] = ir.Function(
            self.module, ir.FunctionType(I64, (I64,) * args, var_arg), name
        )

    def compile_function(self, name: str, program: list[bpf.Instruction]) -> ir.Module:
        func = self.functions[name]

        # Prelude
        self.builder = ir.IRBuilder(func.append_basic_block("entry"))
        (stack_begin, stack_end) = self._alloc_stack(self.builder, 512)
        self.registers = self._alloc_reg(self.builder)
        for reg, arg in zip(self._args_regs(), func.args):
            self.store_reg(reg, arg)
        self.store_reg(bpf.Reg.R10, self.builder.ptrtoint(stack_end, I64))

        # Create basic blocks
        self._create_blocks(program)
        self.exit_block = func.append_basic_block("exit")

        # builder should point to entry, so _compile will branch to the first block
        for pc, ins in enumerate(program):
            if ins is None:
                continue
            self._compile(pc, ins)

        # Epilogue
        self.builder.position_at_end(self.exit_block)
        self.builder.ret(self.load_reg(bpf.Reg.R0))

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

    def _create_block(self, pc: int) -> None:
        if pc not in self.blocks:
            self.blocks[pc] = self.builder.append_basic_block(f"L{pc}")

    def _create_blocks(self, program: list[bpf.Instruction]) -> None:
        self.blocks.clear()
        needs_block = True

        for pc, ins in enumerate(program):
            if needs_block:
                self._create_block(pc)
            match ins:
                case bpf.Jump():
                    needs_block = True
                    if ins.jump_offset is not None:
                        next_pc = pc + 1
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

            case bpf.Jump(opcode, _, dst_reg, offset, imm, func_name):
                match opcode.code:
                    case bpf.JumpCode.CALL:
                        if func_name is None:
                            raise NotImplementedError(
                                f"{opcode.code.name} missing function name"
                            )
                        else:
                            func = self.functions[func_name]
                            args = [self.load_reg(reg) for reg in self._args_regs()]

                            ret = self.builder.call(func, args)
                            # Store return value in R0
                            self.store_reg(bpf.Reg.R0, ret)
                            # Clobber caller-saved registers
                            for reg in self._args_regs():
                                self.store_reg(reg, I64(ir.Undefined))
                    case bpf.JumpCode.EXIT:
                        self.builder.branch(self.exit_block)
                    case _ as code:
                        src = self.load_src(ins)
                        dst = self.load_reg(dst_reg, ins.is_64)
                        match code:
                            case bpf.JumpCode.JEQ:
                                # PC += offset if dst == src
                                cond = self.builder.icmp_unsigned("==", dst, src)
                            case bpf.JumpCode.JGT:
                                # PC += offset if dst > src (unsigned)
                                cond = self.builder.icmp_unsigned(">", dst, src)
                            case bpf.JumpCode.JLT:
                                # PC += offset if dst < src (unsigned)
                                cond = self.builder.icmp_unsigned("<", dst, src)
                            case bpf.JumpCode.JSLT:
                                # PC += offset if dst < src (signed)
                                cond = self.builder.icmp_signed("<", dst, src)
                            case _:
                                raise NotImplementedError(f"{opcode!r}")

                        assert ins.jump_offset is not None

                        next_pc = pc + 1
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

    linker = Linker()
    with open(filename, "rb") as f:
        elf = ELFFile(f)
        linker.add_elf(elf)

    compiler = Compiler()

    # TODO(saleem): implement helper functions
    compiler.declare_function("printf", 1, True)

    for name in linker.functions.keys():
        compiler.declare_function(name)
    for name, program in linker.functions.items():
        compiler.compile_function(name, program)

    print(compiler.module)

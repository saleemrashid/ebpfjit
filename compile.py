#!/usr/bin/env python3
from typing import Iterator, Union

from collections.abc import Buffer
from elftools.elf.elffile import ELFFile
from llvmlite import ir  # type: ignore

import bpf
import itertools
from linker import Linker, SectionId, SymbolId

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

BPF_STACK_SIZE = 131072
BPF_ARGS = 5
BPF_FUNC_TYPE = ir.FunctionType(I64, (I64,) * BPF_ARGS)


class Compiler(object):
    def __init__(self) -> None:
        self.module = ir.Module()
        self.symbols: dict[str, ir.Value] = {}
        self.blocks: dict[int, ir.Block] = {}
        self.unvisited_blocks: set[int] = set()

        self.load: dict[ir.Type, ir.Function] = {}
        self.store: dict[ir.Type, ir.Function] = {}

    @staticmethod
    def _args_regs() -> Iterator[bpf.Reg]:
        for i in range(BPF_ARGS):
            yield bpf.Reg(bpf.Reg.R1 + i)

    def extern_function(
        self, name: str, type: ir.FunctionType, internal: bool = False
    ) -> ir.Function:
        # TODO(saleem): check conflicts
        func = ir.Function(self.module, type, name)
        if internal:
            func.linkage = "internal"
        self.symbols[name] = func
        return func

    def declare_data(
        self,
        name: str,
        elements: list[Union[bytes, tuple[SymbolId, int]]],
        internal: bool = False,
    ) -> None:
        typs = []
        for item in elements:
            match item:
                case Buffer():
                    typs.append(ir.ArrayType(I8, len(item)))
                case (symbol_id, offset):
                    typs.append(I64)

        value = ir.GlobalVariable(self.module, ir.LiteralStructType(typs), name)
        if internal:
            value.linkage = "internal"
        self.symbols[name] = value

    def define_data(
        self, name: str, elements: list[Union[bytes, tuple[SymbolId, int]]]
    ) -> None:
        elems = []
        for item in elements:
            match item:
                case Buffer():
                    elems.append(ir.Constant(ir.ArrayType(I8, len(item)), item))
                case (symbol_id, offset):
                    elems.append(
                        self.symbols[symbol_id.name].ptrtoint(I64).add(I64(offset))
                    )

        value = self.symbols[name]
        value.initializer = ir.Constant(value.value_type, elems)

    def declare_function(self, name: str, pc: int, internal: bool = False) -> None:
        self.extern_function(name, BPF_FUNC_TYPE, internal)

    def allow_region(self, start: ir.Value, end: ir.Value) -> ir.Value:
        return self.builder.call(self.func_allow_region, (self.builder.ptrtoint(start, I64), self.builder.ptrtoint(end, I64)))

    def unallow_region(self, start: ir.Value, end: ir.Value) -> ir.Value:
        return self.builder.call(self.func_unallow_region, (self.builder.ptrtoint(start, I64), self.builder.ptrtoint(end, I64)))

    def compile_function(
        self, name: str, start: int, end: int, text: list[bpf.Instruction]
    ) -> ir.Module:
        func = self.symbols[name]

        # Prelude
        self.builder = ir.IRBuilder(func.append_basic_block("entry"))
        (stack_begin, stack_end) = self._alloc_stack(self.builder, BPF_STACK_SIZE)

        self.allow_region(stack_begin, stack_end)
        for value in self.symbols.values():
            if isinstance(value, ir.Function):
                continue
            region_start = self.builder.ptrtoint(value, I64)
            region_end = self.builder.ptrtoint(value.gep((I64(1),)), I64)
            self.allow_region(region_start, region_end)

        self.registers = self._alloc_reg(self.builder)
        for reg, arg in zip(self._args_regs(), func.args):
            self.store_reg(reg, arg)
        self.store_reg(bpf.Reg.R10, self.builder.ptrtoint(stack_end, I64))

        # Create basic blocks
        self._create_blocks(text, start, end)
        self.exit_block = func.append_basic_block("exit")

        for pc in range(start, end):
            if block := self.blocks.get(pc):
                assert len(block.instructions) == 0
                self.unvisited_blocks.remove(pc)

                if not self.builder.block.is_terminated:
                    self.builder.branch(block)
                self.builder.position_at_end(block)

            ins = text[pc]
            if ins is None:
                continue
            self._compile(pc, ins)

        if not self.builder.block.is_terminated:
            self.builder.branch(self.exit_block)

        # Jumps can cross function boundaries, but LLVM IR doesn't support this. Below we
        # iterate over the reachable basic blocks that aren't part of this function, and
        # compile them into the function as if they were.
        while self.unvisited_blocks:
            pc = self.unvisited_blocks.pop()
            block = self.blocks[pc]
            assert len(block.instructions) == 0

            self.builder.position_at_end(block)
            for pc in itertools.count(pc):
                # FIXME(saleem): LLVM can omit the epilogue for noreturn calls.
                # How can we best handle that, without knowing if a call is noreturn?
                if pc == len(text):
                    self.builder.branch(self.exit_block)
                    break

                ins = text[pc]
                if ins is None:
                    continue
                self._compile(pc, ins)

                if block.is_terminated:
                    break
                elif next_block := self.blocks.get(pc + 1):
                    self.builder.branch(next_block)
                    break

        # Epilogue
        self.builder.position_at_end(self.exit_block)

        self.unallow_region(stack_begin, stack_end)
        for value in self.symbols.values():
            if isinstance(value, ir.Function):
                continue
            region_start = self.builder.ptrtoint(value, I64)
            region_end = self.builder.ptrtoint(value.gep((I64(1),)), I64)
            self.unallow_region(region_start, region_end)

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

    def _create_block(self, pc: int) -> ir.Block:
        if block := self.blocks.get(pc):
            return block
        else:
            block = self.builder.append_basic_block(f"L{pc}")
            self.blocks[pc] = block
            self.unvisited_blocks.add(pc)
            return block

    def _create_blocks(self, text: list[bpf.Instruction], start: int, end: int) -> None:
        self.blocks.clear()
        needs_block = True

        for pc in range(start, end):
            ins = text[pc]
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
        self.builder.comment(f"{pc=}, {ins!r}")
        match ins:
            case bpf.Alu(opcode, src_reg, dst_reg, offset, imm):
                mask = I64(63) if ins.is_64 else I32(31)
                zero = I64(0) if ins.is_64 else I32(0)

                src = self.load_src(ins)
                dst = self.load_reg(dst_reg, ins.is_64)

                match (offset, opcode.code):
                    case (0, _):
                        sdiv = False
                    case (1, bpf.AluCode.DIV | bpf.AluCode.MOD):
                        sdiv = True
                    case _:
                        raise ValueError(
                            f"invalid offset {offset} for {opcode.code.name}"
                        )

                match opcode.code:
                    case bpf.AluCode.ADD:
                        # dst += src
                        dst = self.builder.add(dst, src)
                    case bpf.AluCode.SUB:
                        # dst -= src
                        dst = self.builder.sub(dst, src)
                    case bpf.AluCode.MUL:
                        # dst *= src
                        dst = self.builder.mul(dst, src)
                    case bpf.AluCode.DIV:
                        if sdiv:
                            # result = (dst s/ src)
                            result = self.builder.sdiv(dst, src)
                        else:
                            # result = (dst / src)
                            result = self.builder.udiv(dst, src)
                        # dst = (src != 0) ? result : 0
                        dst = self.builder.select(
                            self.builder.icmp_unsigned("!=", src, zero), result, zero
                        )
                    case bpf.AluCode.OR:
                        # dst |= src
                        dst = self.builder.or_(dst, src)
                    case bpf.AluCode.AND:
                        # dst &= src
                        dst = self.builder.and_(dst, src)
                    case bpf.AluCode.LSH:
                        # dst <<= (src & mask)
                        dst = self.builder.shl(dst, self.builder.and_(src, mask))
                    case bpf.AluCode.RSH:
                        # dst >>= (src & mask)
                        dst = self.builder.lshr(dst, self.builder.and_(src, mask))
                    case bpf.AluCode.NEG:
                        # dst = -dst
                        dst = self.builder.neg(dst)
                    case bpf.AluCode.MOD:
                        if sdiv:
                            # result = (dst s% src)
                            result = self.builder.srem(dst, src)
                        else:
                            # result = (dst % src)
                            result = self.builder.urem(dst, src)
                        # dst = (src != 0) ? result : dst
                        dst = self.builder.select(
                            self.builder.icmp_unsigned("!=", src, zero), result, dst
                        )
                    case bpf.AluCode.XOR:
                        # dst ^= src
                        dst = self.builder.xor(dst, src)
                    case bpf.AluCode.MOV:
                        # dst = src
                        dst = src
                    case bpf.AluCode.ARSH:
                        # dst s>>= (src & mask)
                        dst = self.builder.ashr(dst, self.builder.and_(src, mask))
                    case bpf.AluCode.END:
                        # byte swap operations
                        match ins.imm:
                            case 16:
                                dst = self.builder.trunc(dst, I16)
                            case 32:
                                dst = self.builder.trunc(dst, I32)
                            case 64:
                                dst = self.builder.zext(dst, I64)
                            case _:
                                raise ValueError(
                                    f"invalid byte swap {ins.imm} for {opcode.code.name}"
                                )

                        if ins.is_64 or ins.opcode.source == bpf.Source.X:
                            dst = self.builder.bswap(dst)

                        dst = self.builder.zext(dst, I64)
                    case _:
                        raise NotImplementedError(f"{opcode!r}")

                self.store_reg(dst_reg, dst, ins.is_64)

            case bpf.Jump(opcode, _, dst_reg, offset, imm, symbol):
                match opcode.code:
                    case bpf.JumpCode.CALL:
                        if opcode.source == bpf.Source.X:
                            # FIXME(saleem): check the function target of course
                            func = self.builder.inttoptr(
                                self.load_reg(bpf.Reg(imm)), BPF_FUNC_TYPE.as_pointer()
                            )
                        else:
                            func = self.symbols[symbol.name]

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
                            case bpf.JumpCode.JA:
                                cond = None
                            case bpf.JumpCode.JEQ:
                                # PC += offset if dst == src
                                cond = self.builder.icmp_unsigned("==", dst, src)
                            case bpf.JumpCode.JGT:
                                # PC += offset if dst > src (unsigned)
                                cond = self.builder.icmp_unsigned(">", dst, src)
                            case bpf.JumpCode.JGE:
                                # PC += offset if dst >= src (unsigned)
                                cond = self.builder.icmp_unsigned(">=", dst, src)
                            case bpf.JumpCode.JNE:
                                # PC += offset if dst != src
                                cond = self.builder.icmp_unsigned("!=", dst, src)
                            case bpf.JumpCode.JSGT:
                                # PC += offset if dst > src (signed)
                                cond = self.builder.icmp_signed(">", dst, src)
                            case bpf.JumpCode.JLT:
                                # PC += offset if dst < src (unsigned)
                                cond = self.builder.icmp_unsigned("<", dst, src)
                            case bpf.JumpCode.JLE:
                                # PC += offset if dst <= src (unsigned)
                                cond = self.builder.icmp_unsigned("<=", dst, src)
                            case bpf.JumpCode.JSLT:
                                # PC += offset if dst < src (signed)
                                cond = self.builder.icmp_signed("<", dst, src)
                            case bpf.JumpCode.JSLE:
                                # PC += offset if dst <= src (signed)
                                cond = self.builder.icmp_signed("<=", dst, src)
                            case _:
                                raise NotImplementedError(f"{opcode!r}")

                        assert ins.jump_offset is not None

                        next_pc = pc + 1
                        target = next_pc + ins.jump_offset

                        if cond is None:
                            self.builder.branch(self._create_block(target))
                        else:
                            self.builder.cbranch(
                                cond,
                                self._create_block(target),
                                self._create_block(next_pc),
                            )

            case bpf.LoadImm64(opcode, src, dst_reg, offset, _, _, addr):
                match src:
                    case bpf.LoadSource.IMM64:
                        if addr is None:
                            result = I64(ins.imm64)
                        else:
                            # TODO(saleem): this should probably check that imm64 == 0 for non-pointers
                            result = self.builder.add(
                                self.builder.ptrtoint(self.symbols[ins.addr.name], I64),
                                I64(ins.imm64),
                            )
                    case _:
                        raise NotImplementedError(f"{src!r}")

                self.store_reg(dst_reg, result)

            case bpf.LoadStore(opcode, src_reg, dst_reg, offset, imm):
                size_type = BPF_SIZE_TO_TYPE[opcode.size]

                if opcode.ins_class == bpf.InsClass.LDX:
                    # result = *(unsigned size *) (src + offset)
                    src_ptr = self.builder.inttoptr(
                        self.builder.add(self.load_reg(src_reg), I64(offset)),
                        size_type.as_pointer(),
                    )
                    result = self.builder.call(self.load[size_type], (src_ptr,))

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
                    self.builder.call(self.store[size_type], (dst_ptr, src))

            case _:
                raise NotImplementedError(f"{ins!r}")


if __name__ == "__main__":
    import sys

    filenames = sys.argv[1:]

    linker = Linker()

    for filename in filenames:
        with open(filename, "rb") as f:
            elf = ELFFile(f)
            linker.add_elf(elf)

    compiler = Compiler()

    for ty in (I8, I16, I32, I64):
        compiler.load[ty] = compiler.extern_function(
            f"load{ty.width}", ir.FunctionType(ty, (ty.as_pointer(),))
        )
        compiler.store[ty] = compiler.extern_function(
            f"store{ty.width}", ir.FunctionType(ir.VoidType(), (ty.as_pointer(), ty))
        )

    # TODO(saleem): implement helper functions
    compiler.func_allow_region = compiler.extern_function("allow_region", ir.FunctionType(ir.VoidType(), (I64, I64)))
    compiler.func_unallow_region = compiler.extern_function("unallow_region", ir.FunctionType(ir.VoidType(), (I64, I64)))

    compiler.extern_function("tap_tx", ir.FunctionType(I64, (I64,) * BPF_ARGS))
    compiler.extern_function("tap_rx", ir.FunctionType(I64, (I64,) * BPF_ARGS))
    compiler.extern_function("tap_rx_wait", ir.FunctionType(I64, (I64,) * BPF_ARGS))
    compiler.extern_function("micros", ir.FunctionType(I64, (I64,) * BPF_ARGS))

    compiler.extern_function("printf", ir.FunctionType(I64, (I64,), True))
    compiler.extern_function("my_malloc", ir.FunctionType(I64, (I64,)))
    compiler.extern_function("my_free", ir.FunctionType(I64, (I64,)))
    compiler.extern_function("__ctzsi2", ir.FunctionType(I64, (I64,)))
    compiler.extern_function("__ctzti2", ir.FunctionType(I64, (I64,)))
    compiler.extern_function(
        "write",
        ir.FunctionType(
            I64,
            (
                I64,
                I64,
                I64,
            ),
        ),
    )

    # TODO(saleem): this is hacky, but I'm prototyping the compiler API so it doesn't matter

    for symbol_id, symbol in linker.symbols.items():
        if symbol.section == SectionId.Text:
            compiler.declare_function(
                symbol_id.name, symbol.start // 8, symbol_id.file_idx is not None
            )
        else:
            compiler.declare_data(
                symbol_id.name,
                linker.symbol_values[symbol_id],
                symbol_id.file_idx is not None,
            )
    for symbol_id, symbol in linker.symbols.items():
        if symbol.section == SectionId.Text:
            compiler.compile_function(
                symbol_id.name, symbol.start // 8, symbol.end // 8, linker.program
            )
        else:
            compiler.define_data(symbol_id.name, linker.symbol_values[symbol_id])

    print(compiler.module)

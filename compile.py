#!/usr/bin/env python3
from typing import Iterator, Union

from elftools.elf.elffile import ELFFile
from llvmlite import ir  # type: ignore

import bpf
import itertools
from linker import Linker, SectionId, SymbolId, Symbol, BPF_INSTRUCTION_SIZE
from llvmutils import GlobalAlias

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
        self.symbols: dict[SymbolId, ir.Value] = {}
        self.blocks: dict[int, ir.Block] = {}
        self.unvisited_blocks: set[int] = set()
        self.sections: dict[SectionId, ir.Value] = {}

        self.load_funcs: dict[ir.Type, ir.Function] = {}
        self.store_funcs: dict[ir.Type, ir.Function] = {}

    @staticmethod
    def _args_regs() -> Iterator[bpf.Reg]:
        for i in range(BPF_ARGS):
            yield bpf.Reg(bpf.Reg.R1 + i)

    def declare_data(
        self,
        symbol_id: SymbolId,
        symbol: Symbol,
    ) -> None:
        aliasee = (
            self.sections[symbol.section]
            .ptrtoint(I64)
            .add(I64(symbol.start))
            .inttoptr(I8.as_pointer())
        )
        if symbol_id.file_idx is None:
            name = symbol_id.name
            linkage = None
        else:
            name = f"[{symbol_id.file_idx}]:{symbol_id.name}"
            linkage = "private"

        alias = GlobalAlias(self.module, aliasee, name)
        alias.linkage = linkage
        self.symbols[symbol_id] = alias

    def declare_section(
        self, section: SectionId, elements: list[Union[bytes, tuple[SymbolId, int]]]
    ) -> None:
        typs = []
        for item in elements:
            match item:
                case bytes() | bytearray():
                    typs.append(ir.ArrayType(I8, len(item)))
                case (_, _):
                    typs.append(I64)

        # TODO(saleem): tidy up name mangling?
        name = f"section .{section.name.lower()}"
        variable = ir.GlobalVariable(self.module, ir.LiteralStructType(typs), name)
        variable.linkage = "private"
        self.sections[section] = variable

    def define_section(
        self, section: SectionId, elements: list[Union[bytes, tuple[SymbolId, int]]]
    ) -> None:
        elems = []
        for item in elements:
            match item:
                case bytes() | bytearray():
                    elems.append(ir.Constant(ir.ArrayType(I8, len(item)), item))
                case (symbol_id, offset):
                    elems.append(self.symbols[symbol_id].ptrtoint(I64).add(I64(offset)))

        value = ir.Constant.literal_struct(elems)
        variable = self.sections[section]
        variable.initializer = value

    def allow_region(self, start: ir.Value, end: ir.Value) -> ir.Value:
        # return self.builder.call(self.func_allow_region, (self.builder.ptrtoint(start, I64), self.builder.ptrtoint(end, I64)))
        pass

    def unallow_region(self, start: ir.Value, end: ir.Value) -> ir.Value:
        # return self.builder.call(self.func_unallow_region, (self.builder.ptrtoint(start, I64), self.builder.ptrtoint(end, I64)))
        pass

    def load_mem(self, src: ir.Value) -> ir.Value:
        return self.builder.call(self.load_funcs[src.type.pointee], (src,))

    def store_mem(self, dst: ir.Value, src: ir.Value) -> ir.Value:
        return self.builder.call(self.store_funcs[dst.type.pointee], (dst, src))

    def extern_function(self, name: str, type: ir.FunctionType) -> ir.Function:
        return self.declare_function(SymbolId(name, False, None), type)

    def declare_function(
        self, symbol: SymbolId, type: ir.FunctionType = BPF_FUNC_TYPE
    ) -> ir.Function:
        # TODO(saleem): deduplicate this with declare_data
        if symbol.file_idx is None:
            name = symbol.name
            linkage = None
        else:
            name = f"[{symbol.file_idx}]:{symbol.name}"
            linkage = "private"

        func = ir.Function(self.module, type, name)
        func.linkage = linkage
        self.symbols[symbol] = func
        return func

    def compile_function(
        self, symbol_id: SymbolId, symbol: Symbol, text: list[bpf.Instruction[SymbolId]]
    ) -> ir.Module:
        func = self.symbols[symbol_id]
        start = symbol.start // BPF_INSTRUCTION_SIZE
        end = symbol.end // BPF_INSTRUCTION_SIZE

        # Prelude
        self.builder = ir.IRBuilder(func.append_basic_block("entry"))
        (stack_begin, stack_end) = self._alloc_stack(BPF_STACK_SIZE)

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
        self._dealloc_stack(BPF_STACK_SIZE)

        self.unallow_region(stack_begin, stack_end)
        for value in self.symbols.values():
            if isinstance(value, ir.Function):
                continue
            region_start = self.builder.ptrtoint(value, I64)
            region_end = self.builder.ptrtoint(value.gep((I64(1),)), I64)
            self.unallow_region(region_start, region_end)

        self.builder.ret(self.load_reg(bpf.Reg.R0))

    def _alloc_stack(self, size: int) -> tuple[ir.Value, ir.Value]:
        stack_begin = self.builder.call(self.stack_alloc_func, (I64(size),))
        stack_end = self.builder.gep(stack_begin, (I64(size),))
        return (stack_begin, stack_end)

    def _dealloc_stack(self, size: int):
        self.builder.call(self.stack_dealloc_func, (I64(size),))

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

    def _create_blocks(
        self, text: list[bpf.Instruction[SymbolId]], start: int, end: int
    ) -> None:
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

    def load_src(self, ins: Union[bpf.Alu, bpf.Jump[SymbolId]]) -> ir.Value:
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

    def _compile(self, pc: int, ins: bpf.Instruction[SymbolId]) -> None:
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
                            assert symbol is not None
                            func = self.symbols[symbol]

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

            case bpf.LoadImm64(opcode, src, dst_reg, offset, _, _, symbol):
                match src:
                    case bpf.LoadSource.IMM64:
                        if symbol is None:
                            result = I64(ins.imm64)
                        else:
                            # TODO(saleem): this should probably check that imm64 == 0 for non-pointers
                            result = self.builder.add(
                                self.builder.ptrtoint(self.symbols[symbol], I64),
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
                    result = self.load_mem(src_ptr)

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
                    self.store_mem(dst_ptr, src)

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

    compiler.stack_alloc_func = compiler.extern_function("shim_stack_alloc", ir.FunctionType(I8.as_pointer(), (I64,)))
    compiler.stack_dealloc_func = compiler.extern_function("shim_stack_dealloc", ir.FunctionType(ir.VoidType(), (I64,)))
    compiler.extern_function("shim_heap_start", ir.FunctionType(I64, ()))
    compiler.extern_function("shim_heap_size", ir.FunctionType(I64, ()))

    for ty in (I8, I16, I32, I64):
        compiler.load_funcs[ty] = compiler.extern_function(
            f"shim_load{ty.width}", ir.FunctionType(ty, (ty.as_pointer(),))
        )
        compiler.store_funcs[ty] = compiler.extern_function(
            f"shim_store{ty.width}", ir.FunctionType(ir.VoidType(), (ty.as_pointer(), ty))
        )

    # TODO(saleem): implement helper functions
    compiler.func_allow_region = compiler.extern_function(
        "allow_region", ir.FunctionType(ir.VoidType(), (I64, I64))
    )
    compiler.func_unallow_region = compiler.extern_function(
        "unallow_region", ir.FunctionType(ir.VoidType(), (I64, I64))
    )

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

    for section, struct in linker.section_structs.items():
        if section == SectionId.Text:
            continue
        compiler.declare_section(section, struct)

    for symbol_id, symbol in linker.symbols.items():
        if symbol.section == SectionId.Text:
            compiler.declare_function(symbol_id)
        else:
            compiler.declare_data(symbol_id, symbol)
    for symbol_id, symbol in linker.symbols.items():
        if symbol.section == SectionId.Text:
            compiler.compile_function(symbol_id, symbol, linker.program)

    for section, struct in linker.section_structs.items():
        if section == SectionId.Text:
            continue
        compiler.define_section(section, struct)

    for section_id, section in compiler.sections.items():
        s = f"shim_{section_id.name.lower()}"
        GlobalAlias(compiler.module, section.gep([I64(0)]), f"{s}_start")
        GlobalAlias(compiler.module, section.gep([I64(1)]), f"{s}_end")

    print(compiler.module)

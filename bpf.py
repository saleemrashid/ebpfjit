import enum
from typing import NamedTuple, Optional, Union


class _IntEnum(enum.IntEnum):
    def __repr__(self) -> str:
        return self.name


class InsClass(_IntEnum):
    LD = 0x0
    LDX = 0x1
    ST = 0x2
    STX = 0x3
    ALU = 0x4
    JMP = 0x5
    JMP32 = 0x6
    ALU64 = 0x7

    def is_load(self) -> bool:
        return self in (self.LD, self.LDX)

    def is_store(self) -> bool:
        return self in (self.ST, self.STX)

    def is_alu(self) -> bool:
        return self in (self.ALU, self.ALU64)

    def is_jump(self) -> bool:
        return self in (self.JMP, self.JMP32)


@enum.verify(enum.UNIQUE, enum.CONTINUOUS)
class Reg(_IntEnum):
    R0 = 0
    R1 = 1
    R2 = 2
    R3 = 3
    R4 = 4
    R5 = 5
    R6 = 6
    R7 = 7
    R8 = 8
    R9 = 9
    R10 = 10


class Source(_IntEnum):
    K = 0x0
    X = 0x1


class AluCode(_IntEnum):
    ADD = 0x0
    SUB = 0x1
    MUL = 0x2
    DIV = 0x3
    OR = 0x4
    AND = 0x5
    LSH = 0x6
    RSH = 0x7
    NEG = 0x8
    MOD = 0x9
    XOR = 0xA
    MOV = 0xB
    ARSH = 0xC
    END = 0xD


class JumpCode(_IntEnum):
    JA = 0x0
    JEQ = 0x1
    JGT = 0x2
    JGE = 0x3
    JSET = 0x4
    JNE = 0x5
    JSGT = 0x6
    JSGE = 0x7
    CALL = 0x8
    EXIT = 0x9
    JLT = 0xA
    JLE = 0xB
    JSLT = 0xC
    JSLE = 0xD


class Mode(_IntEnum):
    IMM = 0x0
    ABS = 0x1
    IND = 0x2
    MEM = 0x3
    MEMSX = 0x4
    ATOMIC = 0x5


class Size(_IntEnum):
    W = 0x0
    H = 0x1
    B = 0x2
    DW = 0x3


class AluOpcode(NamedTuple):
    code: AluCode
    source: Source
    ins_class: InsClass


class JumpOpcode(NamedTuple):
    code: JumpCode
    source: Source
    ins_class: InsClass


class LoadStoreOpcode(NamedTuple):
    mode: Mode
    size: Size
    ins_class: InsClass


class Alu(NamedTuple):
    opcode: AluOpcode
    src_reg: Reg
    dst_reg: Reg
    offset: int
    imm: int

    @property
    def size(self) -> int:
        return 1

    @property
    def is_64(self) -> bool:
        return self.opcode.ins_class == InsClass.ALU64


class Jump(NamedTuple):
    opcode: JumpOpcode
    src_reg: Reg
    dst_reg: Reg
    offset: int
    imm: int

    @property
    def size(self) -> int:
        return 1

    @property
    def is_64(self) -> bool:
        return self.opcode.ins_class == InsClass.JMP

    @property
    def jump_offset(self) -> Optional[int]:
        match self.opcode.code:
            case JumpCode.JA if not self.is_64:
                return self.imm
            case JumpCode.CALL | JumpCode.EXIT:
                return None
            case _:
                return self.offset


class LoadStore(NamedTuple):
    opcode: LoadStoreOpcode
    src_reg: Reg
    dst_reg: Reg
    offset: int
    imm: int

    @property
    def size(self) -> int:
        return 1


class LoadSource(_IntEnum):
    IMM64 = 0x0
    MAP_BY_FD = 0x1
    MAP_VAL_BY_FD = 0x2
    VAR_ADDR = 0x3
    CODE_ADDR = 0x4
    MAP_BY_IDX = 0x5
    MAP_VAL_BY_IDX = 0x6


class LoadImm64(NamedTuple):
    opcode: LoadStoreOpcode
    src: LoadSource
    dst_reg: Reg
    offset: int
    imm32: int
    next_imm: int

    @property
    def size(self) -> int:
        return 2

    @property
    def imm64(self) -> int:
        # TODO(saleem): is this sign-extended properly?
        return (self.next_imm << 32) | (self.imm32 & 0xFFFFFFFF)


Opcode = Union[AluOpcode, JumpOpcode, LoadStoreOpcode]
Instruction = Union[Alu, Jump, LoadStore, LoadImm64]

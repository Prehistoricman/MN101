#include "mn101.hpp"
#include <segregs.hpp>

typedef enum {
    OPG_NONE = 0,
    OPG_D_SRC,
    OPG_D_DST,
    OPG_DW_SRC,
    OPG_DW_DST,
    OPG_D0_DW_DST,
    OPG_D1_DW_DST,
    OPG_DIVU_DN,
    OPG_A_8,
    OPG_A_SRC, 
    OPG_A_DST,
    OPG_IMM4,
    OPG_IMM4_S,
    OPG_IMM8,
    OPG_IMM8_S,
    OPG_IMM12,
    OPG_IMM16,
    OPG_IO8,
    OPG_BRANCH4,
    OPG_BRANCH7,
    OPG_BRANCH11,
    OPG_BRANCH18,
    OPG_BRANCH20,
    OPG_CALL12,
    OPG_CALL16,
    OPG_CALL18,
    OPG_CALL20,
    OPG_CALLTBL4,
    OPG_REG_SP,
    OPG_REG_PSW,
    OPG_REG_HA,
    OPG_BITPOS,
    OPG_REP3,

    OPGF_RELATIVE = 0x100,

    OPGF_MEM8  = 0x200,
    OPGF_MEM16 = 0x400,
    OPGF_MEM_MASK = 0x600,

    OPGF_SHOWAT_0 = 0x1000,
    OPGF_SHOWAT_1 = 0x2000,
    OPGF_SHOWAT_2 = 0x3000,
    OPGF_SHOWAT_MASK = 0x7000

} opgen_t;

#define FLAG_SRCOFF_SP 0x01
#define FLAG_DSTOFF_SP 0x02

typedef struct
{
    uchar code;
    uchar mask;
    ins_enum_t mnemonic;
    uint32 op[3];

} parseinfo_t;

static parseinfo_t parseTable[] = {
#include "parsetable0.gen.c"
};

static parseinfo_t parseTableExtension2[] = {
#include "parsetable1.gen.c"
};

static parseinfo_t parseTableExtension3[] = {
#include "parsetable2.gen.c"
};


static class parseState_t
{
public:
    ea_t pc;
    ea_t ptr;
    uint32 code;
    uchar sz;
    uchar insbyte;

    void reset(insn_t &insn)
    {
        code = 0;
        sz = 0;
        uchar H = get_sreg(insn.ea, rVh);
        ptr = pc = (insn.ea << 1) + H;
    }

    uint32 fetchNibble()
    {
        uchar nibble;
        if (ptr & 1)
            nibble = get_byte(ptr >> 1) >> 4;
        else
            nibble = get_byte(ptr >> 1) & 0xF;

        QASSERT(256, nibble <= 0xF);
        code = (code << 4) | nibble;
        sz++;
        ptr++;
        msg("parseState nibble %X\n", nibble);
        return nibble;
    }

    // This is unaligned byte fetch. Note it is not the same as 2x fetchNibble()
    uint32 fetchByte()
    {
        uchar byte;
        if (ptr & 1)
        {
            byte = get_byte(ptr >> 1) >> 4;
            byte |= get_byte((ptr >> 1) + 1) << 4;
        }
        else
            byte = get_byte(ptr >> 1);

        code = (code << 8) | byte;
        sz += 2;
        ptr += 2;
        return byte;
    }

    bool compareMask(const parseinfo_t *pi)
    {
        if ((code & pi->mask) == pi->code)
        {
            // Save the first two nibbles for operands parsing
            insbyte = code;
            return true;
        }
        return false;
    }

} parseState;

static void setCodeAddrValue(op_t &op, ea_t addr)
{
    op.addr = addr >> 1;
    op.value = addr;
}

#define IOTOP 0x3F00
#define SRVT 0x4080
#define SIGN_EXTEND(nbits, val) (((val) << (32 - (nbits))) >> (32 - (nbits)))

static bool parseOperand(insn_t &insn, op_t &op, int type)
{
    uchar v;
    signed int imm;
    signed char imm8;
    switch (type)
    {
    case OPG_NONE:
        break;
    case OPG_D_SRC:
        v = (parseState.insbyte & 0xC) >> 2;
        op.type = o_reg;
        op.reg = OP_REG_D + v;
        break;
    case OPG_D_DST:
        v = parseState.insbyte & 0x3;
        op.type = o_reg;
        op.reg = OP_REG_D + v;
        break;
    case OPG_DW_SRC:
        v = (parseState.insbyte & 0x2) >> 1;
        op.type = o_reg;
        op.reg = OP_REG_DW + v;
        break;
    case OPG_DW_DST:
        v = parseState.insbyte & 0x1;
        op.type = o_reg;
        op.reg = OP_REG_DW + v;
        break;
    case OPG_D0_DW_DST:
    case OPG_D1_DW_DST:
        v = parseState.insbyte & 0x1;
        op.type = o_reg;
        op.reg = OP_REG_D + v * 2;
        if (type == OPG_D1_DW_DST)
            op.reg++;
        break;
    case OPG_DIVU_DN:
        v = parseState.insbyte & 0x1;
        op.type = o_reg;
        if (v == 0)
            op.reg = OP_REG_D2;
        else
            op.reg = OP_REG_D0;
        break;
    case OPG_A_8:
        v = (parseState.insbyte & 0x4) >> 2;
        op.type = o_reg;
        op.reg = OP_REG_A + v;
        break;
    case OPG_A_SRC:
        v = (parseState.insbyte & 0x2) >> 1;
        op.type = o_reg;
        op.reg = OP_REG_A + v;
        break;
    case OPG_A_DST:
        v = parseState.insbyte & 0x1;
        op.type = o_reg;
        op.reg = OP_REG_A + v;
        break;

    case OPG_IMM4:
    case OPG_IMM4_S:
        imm = parseState.fetchNibble();
        if (type == OPG_IMM4_S)
        {
            imm = SIGN_EXTEND(4, imm);
            op.flags |= OF_NUMBER;
        }
        op.addr = op.value = imm;
        op.type = o_imm;
        op.dtype = dt_byte;
        break;
    case OPG_IMM8:
    case OPG_IMM8_S:
        imm = parseState.fetchByte();
        if (type == OPG_IMM8_S)
        {
            imm = SIGN_EXTEND(8, imm);
            //op.flags |= OF_NUMBER;
        }
        op.addr = op.value = imm;
        op.type = o_imm;
        op.dtype = dt_byte;
        break;
    case OPG_IMM12:
        imm = parseState.fetchByte();
        imm |= parseState.fetchNibble() << 8;
        op.addr = op.value = imm;
        op.type = o_imm;
        op.dtype = dt_word;
        break;
    case OPG_IMM16:
        imm = parseState.fetchByte();
        imm |= parseState.fetchByte() << 8;
        op.addr = op.value = imm;
        op.type = o_imm;
        op.dtype = dt_word;
        //op.flags |= OF_NUMBER;
        break;
    case OPG_IO8:
        imm = parseState.fetchByte();
        op.addr = op.value = IOTOP + imm;
        op.type = o_mem;
        op.dtype = dt_byte;
        break;

    case OPG_BRANCH4:
        imm = parseState.fetchNibble();
        imm = SIGN_EXTEND(4, imm);
        imm = (imm << 1) | (parseState.insbyte & 1); // Extract H
        setCodeAddrValue(op, parseState.pc + imm + parseState.sz);
        op.type = o_near;
        break;
    case OPG_BRANCH7:
        imm8 = parseState.fetchByte(); //Signed imm#8
        setCodeAddrValue(op, parseState.pc + imm8 + parseState.sz);
        op.type = o_near;
        break;
    case OPG_BRANCH11:
        imm = parseState.fetchByte();
        imm |= parseState.fetchNibble() << 8; //Signed imm#12
        imm = SIGN_EXTEND(12, imm);
        setCodeAddrValue(op, parseState.pc + imm + parseState.sz);
        op.type = o_near;
        break;
    case OPG_BRANCH18:
    case OPG_CALL18:
        imm = parseState.fetchByte();
        imm |= parseState.fetchByte() << 8;
        imm |= (parseState.insbyte & 0x6) << 15; //aa
        imm = (imm << 1) | (parseState.insbyte & 0x1); //H
        setCodeAddrValue(op, imm);
        op.type = o_near;
        break;
    case OPG_BRANCH20:
    case OPG_CALL20:
    {
        uchar u = parseState.fetchNibble();
        v = parseState.fetchNibble();
        imm = parseState.fetchByte();
        imm |= parseState.fetchByte() << 8;
        imm |= (v & 0xE) << 15; //bbb
        imm |= (u & 0x1) << 19; //B
        imm = (imm << 1) | (v & 0x1); //H
        setCodeAddrValue(op, imm);
        op.type = o_near;
    }
    break;

    case OPG_CALL12:
        imm = parseState.fetchByte();
        imm |= parseState.fetchNibble() << 8;
        imm = SIGN_EXTEND(12, imm);
        imm = (imm << 1) | (parseState.insbyte & 0x1); //H
        setCodeAddrValue(op, parseState.pc + imm + parseState.sz);
        op.type = o_near;
        break;
    case OPG_CALL16:
        imm = parseState.fetchByte();
        imm |= parseState.fetchByte() << 8;
        imm = SIGN_EXTEND(16, imm);
        imm = (imm << 1) | (parseState.insbyte & 0x1); //H
        setCodeAddrValue(op, parseState.pc + imm + parseState.sz);
        op.type = o_near;
        break;
    case OPG_CALLTBL4:
    {
        imm = parseState.fetchNibble();
        imm = SRVT + (imm << 2);

        ea_t tblentry = to_ea(insn.cs, imm);
        ea_t ea = get_dword(tblentry);
        setCodeAddrValue(op, ((ea & 0xFFFFF) << 1) | (ea >> 23));
        op.specval = tblentry;
        op.type = o_far;
    }
        break;

    case OPG_REG_SP:
        op.type = o_reg;
        op.reg = OP_REG_SP;
        break;
    case OPG_REG_PSW:
        op.type = o_reg;
        op.reg = OP_REG_PSW;
        break;
    case OPG_REG_HA:
        op.type = o_reg;
        op.reg = OP_REG_HA;
        break;

    case OPG_BITPOS:
    case OPG_REP3:
        imm = parseState.insbyte & 0x7;
        if (type == OPG_BITPOS)
            op.type = o_bitpos;
        else
            op.type = o_imm;
        op.value = imm;
        break;

    default:
        QASSERT(257, 0);
    }

    msg("parseop idx = %d type = %d\n", op.n, op.type);

    return true;
}

static void mergeOps(op_t &src, op_t &dst)
{
    QASSERT(258, &src != &dst);

    dst.type = src.type;
    QASSERT(258, dst.reg == OP_REG_NONE);
    dst.reg = src.reg;
    dst.addr += src.addr;
    dst.value += src.value;
    dst.flags |= src.flags;
    //dst.dtype = src.dtype;

    src.type = 0;
    src.reg = 0;
    src.addr = 0;
    src.value = 0;
    src.flags = 0;
    src.dtype = 0;
}

static bool parseInstruction(insn_t &insn, const parseinfo_t *pTable, size_t tblSize)
{
    const parseinfo_t *ins;
    for (size_t i = 0; i < tblSize; i++)
    {
        ins = &pTable[i];
        if (parseState.compareMask(ins))
        {
            insn.itype = ins->mnemonic;
            msg("mnemonic %d\n", ins->mnemonic);
            int opidx = -1;
            for (int j = 0; j < 3; j++)
            {
                opidx = (ins->op[j] & OPGF_SHOWAT_MASK) >> 12;
                if (opidx != 0)
                    opidx--;
                else
                    opidx = j;
                parseOperand(insn, insn.ops[opidx], ins->op[j] & 0xFF);
                if ((ins->op[j] & OPGF_MEM_MASK) != 0)
                {
                    if (insn.ops[opidx].type == o_reg)
                        insn.ops[opidx].type = o_phrase;
                    else if (insn.ops[opidx].type == o_imm)
                        insn.ops[opidx].type = o_mem;
                    if (ins->op[j] & OPGF_MEM8)
                        insn.ops[opidx].dtype = dt_byte;
                    if (ins->op[j] & OPGF_MEM16)
                        insn.ops[opidx].dtype = dt_word;
                }
                if ((ins->op[j] & OPGF_RELATIVE) != 0)
                {
                    insn.ops[opidx].type = o_displ;
                    insn.ops[opidx].addr = insn.ops[opidx].value;
                }
            }

            // Merge displacement ops
            int dstidx = 0;
            for (int srcidx = 0; srcidx < 3; srcidx++)
            {
                if (insn.ops[srcidx].type == o_displ)
                {
                    QASSERT(258, dstidx > 0);
                    dstidx--;
                }
                if (srcidx != dstidx)
                {
                    mergeOps(insn.ops[srcidx], insn.ops[dstidx]);
                }
                dstidx++;
            }

            return true;
        }
    }

    return false;
}


int idaapi mn101_ana(insn_t &insn)
{
    bool decoded;
    parseState.reset(insn);

    // Get the first byte of instruction
    uchar extension = parseState.fetchNibble();
    msg("ext %d\n", extension);

    // Handle extension codes
    switch (extension)
    {
    case 0x3:
        parseState.fetchNibble();
        parseState.fetchNibble();
        decoded = parseInstruction(insn, parseTableExtension3, qnumber(parseTableExtension3));
        break;

    case 0x2:
        parseState.fetchNibble();
        parseState.fetchNibble();
        decoded = parseInstruction(insn, parseTableExtension2, qnumber(parseTableExtension2));
        break;

    default:
        parseState.fetchNibble();
        decoded = parseInstruction(insn, parseTable, qnumber(parseTable));
        break;
    }

    if (!decoded) {
        msg("not a valid instruction\n");
        return 0;
    }


    // Compiler generally aligns the size of return instructions by a byte
    //TODO: maybe add a user option for this
    /*if (insn.itype == INS_RTS || insn.itype == INS_RTI)
    {
        if ((parseState.sz + parseState.pc) & 1) ++parseState.sz;
        insn.segpref = 0;
    }
    else*/
    {
        // insn.segpref would hold 1 if the last byte was only partially consumed
        insn.segpref = parseState.ptr & 1;
    }

    // Update the command size
    insn.size = (parseState.sz + (parseState.pc & 1)) / 2;
    msg("ana finish mnem = %d %s op0 type = %d\n", insn.itype, insn.get_canon_mnem(), insn.ops[0].type);
    return(insn.size);
}

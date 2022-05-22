#ifndef _MN101_HPP
#define _MN101_HPP

#include "../idaidp.hpp"
#include <ida.hpp>

#include "ins.hpp"

extern netnode helper;

// Define a special op type for bitpos
#define o_bitpos o_idpspec0

enum mn101_registers {
    OP_REG_NONE = 0,

    OP_REG_D,
    OP_REG_D0 = OP_REG_D,
    OP_REG_D1,
    OP_REG_D2,
    OP_REG_D3,

    OP_REG_A,
    OP_REG_A0 = OP_REG_A,
    OP_REG_A1,

    OP_REG_DW,
    OP_REG_DW0 = OP_REG_DW,
    OP_REG_DW1,

    OP_REG_SP,
    OP_REG_PSW,
    OP_REG_HA,

    rVcs,
    rVds,
    rVh,

    OP_REG_LAST,
};


void idaapi mn101_header(outctx_t &ctx);
void idaapi mn101_footer(outctx_t &ctx);

void idaapi mn101_segstart(outctx_t &ctx, segment_t &Sarea);

int idaapi mn101_ana(insn_t &insn);
int idaapi mn101_emu(const insn_t &insn);


#endif

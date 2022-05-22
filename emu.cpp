#include "mn101.hpp"
#include <segregs.hpp>

static bool flow;

static void handle_operand(const insn_t &insn, const op_t &operand, int isread)
{
    ea_t ea = to_ea(insn.cs, operand.addr);

    switch (operand.type)
    {
    case o_void:
        msg("o_void\n");
        break;
    case o_reg:
        msg("o_reg\n");
        break; 
    case o_bitpos:
        msg("o_bitpos\n");
        break;
    case o_phrase:
        msg("o_phrase\n");
        break;

    case o_displ:
        msg("o_displ\n");
        set_immd(insn.ea);
        if (op_adds_xrefs(insn.flags, operand.n))
            insn.add_off_drefs(operand, dr_O, OOF_ADDR);
        break;

    case o_imm:
        msg("o_imm\n");
        set_immd(insn.ea);

        // Instructions of type 'MOVW imm,Am' with imm != 0 point that imm is most likely an address
        if (!is_defarg(insn.flags, operand.n) && (insn.itype == INS_MOVW) && (operand.value != 0)
            && (insn.Op2.type == o_reg) && (insn.Op2.reg >= OP_REG_A0) && (insn.Op2.reg <= OP_REG_A1))
        {
            op_offset(insn.ea, operand.n, REF_OFF16);
        }
        if (op_adds_xrefs(insn.flags, operand.n)) {
            //TODO old code: ua_add_off_drefs(operand, dr_O);
            insn.add_off_drefs(operand, dr_O, 0);
        }
        break;

    case o_mem:
        msg("o_mem\n");
        insn.create_op_data(operand.offb, ea, operand.dtype);
        /*if (!isread)
            doVar(ea);*/ //TODO: This function was removed with no specified replacement in the porting guide
        insn.add_dref(operand.offb, ea, isread ? dr_R : dr_W);
        break;

    case o_far: // Used for JSRV
        msg("o_far\n");
        insn.add_dref(operand.offb, operand.specval, isread ? dr_R : dr_W);
        insn.create_op_data(operand.offb, operand.specval, dt_dword);
        //fallthrough
    case o_near:
        msg("o_near\n");
        if (has_insn_feature(insn.itype, CF_CALL))
        {
            insn.add_cref(operand.offb, ea, fl_CN);
            flow = func_does_return(ea);
        }
        else
        {
            insn.add_cref(operand.offb, ea, fl_JN);
        }

        // Mark the jump target byte address if it has halfbyte offset
        // But only if it is not already inside a processed function,
        // otherwise we could destroy it by forcing segreg change
        if (get_func(ea) == NULL)
        {
            split_sreg_range(ea, rVh, operand.value & 1, SR_auto);
        }
        break;

    default:
        warning("%a %s,%d: bad optype %d",
            insn.ea, insn.get_canon_mnem(), operand.n, operand.type);
        break;
    }
}


int idaapi mn101_emu(const insn_t &insn)
{
    uint32 Feature = insn.get_canon_feature();
    msg("emu feature = 0x%X\n", Feature);
    flow = ((Feature & CF_STOP) == 0);

    if (Feature & CF_USE1) handle_operand(insn, insn.ops[0], 1);
    if (Feature & CF_USE2) handle_operand(insn, insn.ops[1], 1);
    if (Feature & CF_USE3) handle_operand(insn, insn.ops[2], 1);
    if (Feature & CF_CHG1) handle_operand(insn, insn.ops[0], 0);
    if (Feature & CF_CHG2) handle_operand(insn, insn.ops[1], 0);
    if (Feature & CF_CHG3) handle_operand(insn, insn.ops[2], 0);
    if (Feature & CF_JUMP) remember_problem(PR_JUMP, insn.ea);
    if (flow) insn.add_cref(0, insn.ea + insn.size, fl_F);

    // Mark the next command's start halfbyte
    // Note it should be done even if flow==0 to prevent errors on following instructions autoanalysis
    // But be careful not to mess other functions
    ea_t next = insn.ea + insn.size;
    if (get_func(next) == NULL)
    {
        split_sreg_range(next, rVh, insn.segpref, SR_auto);
    }

    return(1);
}

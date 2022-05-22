#include "mn101.hpp"

extern qstring device;

class out_mn101_t : public outctx_t
{
public:
    bool out_operand(const op_t &x);
    void out_insn(void);
private:
    void OutVarName(const op_t& x);
};

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_mn101_t)

void out_mn101_t::OutVarName(const op_t &x)
{
    ea_t addr = x.addr;
    bool H = 0;
    // For branch ops x.value holds halfbyte address and x.addr holds byte address
    if (x.addr != x.value)
        H = x.value & 1;

    ea_t target = to_ea(map_code_ea(insn, x), addr);
    if (!out_name_expr(x, target, addr))
    {
        out_value(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_32);
        remember_problem(PR_NONAME, insn.ea);
    }
    if (H) out_symbol('_');
}

bool out_mn101_t::out_operand(const op_t &x) {
    switch (x.type)
    {
    case o_phrase:
    case o_displ:
        out_symbol('(');
        // Do not add imm-offset when its zero
        if (x.addr != 0)
        {
            out_value(x, OOF_ADDR);
            out_symbol(',');
        }
        out_register(ph.reg_names[x.reg]);
        out_symbol(')');
        break;

    case o_reg:
        out_register(ph.reg_names[x.reg]);
        break;

    case o_bitpos:
    case o_imm:
        out_value(x, OOF_SIGNED | OOFW_32);
        break;

    case o_far:
    case o_near:
        OutVarName(x);
        break;

    case o_mem:
        out_symbol('(');
        OutVarName(x);
        out_symbol(')');
        break;

    case o_void:
        return 0;

    default:
        warning("out: %a: bad optype %d", insn.ea, x.type);
        break;
    }
    return 1;
}

void out_mn101_t::out_insn(void)
{
    out_mnemonic();

    //First operand
    if (insn.ops[0].type != o_void)
        out_one_operand(0);

    //Second and third operand
    for (int i = 1; i <= 2; i++) {
        if (insn.ops[i].type == o_void) {
            break;
        }
        if (insn.ops[1].type != o_bitpos)
        {
            out_symbol(',');
            out_char(' ');
        }
        out_one_operand(i);
    }

    out_immchar_cmts();
    //if (is_suspop(insn.ea, insn.flags, 0)) out_immchar_cmts();
    //if (is_suspop(insn.ea, insn.flags, 1)) out_immchar_cmts();
    //if (is_suspop(insn.ea, insn.flags, 2)) out_immchar_cmts();

    flush_outbuf();
}

//--------------------------------------------------------------------------
// Listing header
void idaapi mn101_header(outctx_t &ctx)
{
    ctx.gen_header(GH_PRINT_ALL_BUT_BYTESEX, device.c_str());
    ctx.gen_empty_line();
}

//--------------------------------------------------------------------------
// Segment start
void idaapi mn101_segstart(outctx_t &ctx, segment_t &Sarea)
{
    if (is_spec_segm(Sarea.type)) return;

    qstring sname;
    get_segm_name(&sname, &Sarea, 0/*get segment name 'as is'*/);

    ctx.gen_cmt_line("section %s", sname);
}


//--------------------------------------------------------------------------
// Listing footer
void idaapi mn101_footer(outctx_t &ctx)
{
    char buf[MAXSTR];
    char *const end = buf + sizeof(buf);
    if (ash.end != NULL)
    {
        ctx.gen_empty_line();
        char* ptr = buf;// tag_addstr(buf, end, COLOR_ASMDIR, ash.end); //TODO use out_tagon?
        qstring name;
        if (get_colored_name(&name, inf.start_ea) > 0)
        {
            register size_t i = strlen(ash.end);
            do
                APPCHAR(ptr, end, ' ');
            while (++i < 8);
            APPEND(ptr, end, name.begin());
        }
        ctx.flush_buf(buf, inf.indent);
    }
    else
    {
        ctx.gen_cmt_line("end of file");
    }
}

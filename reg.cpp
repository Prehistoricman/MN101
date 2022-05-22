#include "mn101.hpp"

#include <diskio.hpp>
#include <segregs.hpp>

//--------------------------------------------------------------------------
static const char *const mn101_registerNames[] =
{
    "",
    "D0","D1","D2","D3",
    "A0","A1",
    "DW0","DW1",
    "SP", "PSW", "HA",

    "cs","ds", "H"
};

//----------------------------------------------------------------------
//       Prepare global variables & defines for ../iocommon.cpp
//----------------------------------------------------------------------
static netnode helper;
qstring device;
static ioports_t ports;
static const char cfgname[] = "mn101e.cfg";
#include "../iocommon.cpp"


//----------------------------------------------------------------------
static ssize_t idaapi idb_callback(void *, int code, va_list /*va*/)
{
    switch (code)
    {
    case idb_event::closebase:
    case idb_event::savebase:
        helper.supset(0, device.c_str()); //Update device type in the IDB
        break;
    }
    return 0;
}

//----------------------------------------------------------------------
static ssize_t idaapi notify(void*, int msgid, va_list va)
{
    if (msgid != 75 && msgid != 16 && msgid != 20 && msgid != 55) {
        msg("notify: %d ", msgid);
    }
    //int code = invoke_callbacks(HT_IDP, msgid, va);
    //if (code) return code;

    switch (msgid)
    {
    case processor_t::ev_init:
        hook_to_notification_point(HT_IDB, idb_callback);
        helper.create("$ MN101");
        helper.supstr(&device, 0); //Write device type to the IDB
        break;

    case processor_t::ev_term:
        ports.clear();
        unhook_from_notification_point(HT_IDB, idb_callback);
        break;

    case processor_t::ev_newfile:
    {
        if (choose_ioport_device(&device, cfgname, parse_area_line0)) //TODO is parse_area_line0 necessary?
            set_device_name(device.c_str(), IORESP_ALL);
    }
    break;

    case processor_t::ev_creating_segm:
    {
        segment_t *s = va_arg(va, segment_t *);
        // set initial value for pseudosegment register H
        s->defsr[rVh - ph.reg_first_sreg] = 0;
    }
    break;

    case processor_t::ev_out_header:
    {
        outctx_t* ctx = va_arg(va, outctx_t*);
        mn101_header(*ctx);
    } break;

    case processor_t::ev_out_footer:
    {
        outctx_t* ctx = va_arg(va, outctx_t*);
        mn101_footer(*ctx);
    } break;

    case processor_t::ev_out_segstart:
    {
        outctx_t* ctx = va_arg(va, outctx_t*);
        segment_t* segment = va_arg(va, segment_t*);
        msg("segstart at 0x%X\n", segment->start_ea);
        mn101_segstart(*ctx, *segment);
    } break;

    case processor_t::ev_ana_insn:
    {
        insn_t *insn = va_arg(va, insn_t *);
        msg("ana instruction at 0x%X\n", insn->ea);
        return mn101_ana(*insn);
    }

    case processor_t::ev_emu_insn:
    {
        const insn_t *insn = va_arg(va, const insn_t *);
        msg("emu instruction at 0x%X\n", insn->ea);
        return mn101_emu(*insn) ? 1 : -1; //Returns 1 for ok, -1 for delete instruction
    }

    case processor_t::ev_out_insn:
    {
        outctx_t *ctx = va_arg(va, outctx_t *);
        msg("out\n");
        out_insn(*ctx);
        msg("out end\n");
        return 1;
    }

    case processor_t::ev_out_operand:
    {
        outctx_t *ctx = va_arg(va, outctx_t *);
        const op_t *op = va_arg(va, const op_t *);
        msg("out op %d\n", op->n);
        return out_opnd(*ctx, *op) ? 1 : -1;
    }

    default:
        break;
    }
    return 0;
}

static const asm_t mn101asm = {
    AS_COLON | AS_UDATA | ASH_HEXF3 | ASD_DECF0 | ASO_OCTF0 | ASB_BINF0,
    0,                          // User defined flags
    "MN101 assembler",          // Assembler name
    0,                          // Help screen number
    NULL,                       // array of automatically generated header lines
    "org",                      // org directive
    "end",                      // end directive
    ";",                        // comment string
    '"',                        // ASCII string delimiter
    '\'',                       // ASCII char constant delimiter
    "\\\"'",                    // ASCII special chars
    "DB",                       // ASCII string directive
    "DB",                       // byte directive
    "DW",                       // word directive
    "DA",                       // dword  (4 bytes)
    NULL,                       // qword  (8 bytes)
    NULL,                       // oword  (16 bytes)
    NULL,                       // float  (4 bytes)
    NULL,                       // double (8 bytes)
    NULL,                       // long double  (10/12 bytes)
    NULL,                       // packed decimal real
    "#d dup(#v)",               // array keyword
    "DB ?",                     // uninitialized data directive
    "EQU",                      // 'equ' Used if AS_UNEQU is set
    NULL,                       // 'seg ' prefix
    NULL,                       // current IP (instruction pointer) symbol in assembler
    NULL,                       // Generate function header line
    NULL,                       // Generate function footer lines
    NULL,                       // "public" name keyword
    NULL,                       // "weak"   name keyword
    NULL,                       // "extern" name keyword
    NULL,                       // "comm" (communal variable)
    NULL,                       // Get name of type of item at ea or id
    "ALIGN",                    // "align" keyword
    '(', ')',                   // lbrace, rbrace
    NULL,                       // %  mod     assembler time operation
    NULL,                       // &  bit and assembler time operation
    NULL,                       // |  bit or  assembler time operation
    NULL,                       // ^  bit xor assembler time operation
    NULL,                       // ~  bit not assembler time operation
    NULL,                       // << shift left assembler time operation
    NULL,                       // >> shift right assembler time operation
    NULL,                       // size of type (format string)
};


static const asm_t *const asms[] = { &mn101asm, NULL };
#define FAMILY "Panasonic MN101:"
static const char *const shnames[] = { "MN101E", NULL };
static const char *const lnames[] = { FAMILY"Panasonic MN101E", NULL };

// Opcodes of return instructions
static const uchar retcode_1[] = { 0x01 };    // RTS
static const uchar retcode_2[] = { 0x03 };    // RTI
static bytes_t retcodes[] = {
    { sizeof(retcode_1), retcode_1 },
    { sizeof(retcode_2), retcode_2 },
    { 0, NULL }
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------

#define PLFM_MN101 0x8002

processor_t LPH = {
    IDP_INTERFACE_VERSION,
    PLFM_MN101,
    PRN_HEX | PR_SEGS | PR_SGROTHER,
    0,                          // Additional processor flags
    8,                          // 8 bits in a byte for code segments
    8,                          // 8 bits in a byte for other segments

    shnames,                    // array of short processor names
    lnames,                     // array of long processor names

    asms,                       // array of target assemblers

    notify,                     // the kernel event notification callback


    mn101_registerNames,          // Register names
    qnumber(mn101_registerNames), // Number of registers

    rVcs,rVh,                   // Number of first/last segment register
    2,                          // size of a segment register

    rVcs,rVds,                  // Number of CS/DS register

    NULL,                       // Array of typical code start sequences
    retcodes,                   // Array of 'return' instruction opcodes.

    0, INS_LAST,                // icode of the first/last instruction
    Instructions,               // Array of instructions

    0,                          // tbyte size

    { 0,7,15,19 },                     // Number of digits in floating numbers after the decimal point

    INS_RTS,                    // Icode of return instruction

    NULL                        // Unused



    /*

    mn101_ana,                  // analyze an instruction and fill the 'cmd' structure
    mn101_emu,                  // emulate an instruction

    mn101_out,                  // generate a text representation of an instruction
    mn101_outop,                // generate a text representation of an operand
    intel_data,                 // generate a text representation of a data item
    */
};

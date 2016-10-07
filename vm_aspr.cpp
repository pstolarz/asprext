/*
   Copyright (c) 2016 Piotr Stolarz
   asprext: ASProtect reverse engineering & analysis WinDbg extension

   Distributed under the GNU General Public License (the License)
   see accompanying file LICENSE for details.

   This software is distributed WITHOUT ANY WARRANTY; without even the
   implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
   See the License for more information.
 */

#include "common.h"
#include "vm_aspr.h"
#include "aip_aspr.h"

extern "C" {
#include "disasm/disasm.h"
}

/* VM context */
typedef struct _vmctx_t
{
    UINT32 eax;
    UINT32 ebx;
    UINT32 ecx;
    UINT32 edx;
    UINT32 esi;
    UINT32 edi;
    UINT32 ebp;
    UINT32 esp;
    UINT32 eip;
    UINT32 flags;
    ULONG64 opcdsc_addr;  /* currently executed opc description */
} vmctx_t;

/* max VM context length */
#define MAX_VMCTX       0xc4

/* indexes of the vmctx_t fields in
   version specific vm context structs */
static const size_t ASPR_1_6X_VMCTX_OFFS[] = {
    0x20, 0x2c, 0x24, 0x28, 0x38, 0x3c, 0x34, 0x30, 0x44, 0x48, 0xb5};

/* version specific vm context lengths */
static const size_t ASPR_1_6X_VMCTX_LEN = 0xb9;

/* numer of confidental data access handlers */
#define NUM_HNDL            10U

/* ASPR vm input */
typedef struct _vmin_aspr_t
{
    ULONG64 opcdscs_addr;   /* opcode descs addr */
    UINT32 n_opcdscs;       /* number of opcdsc elems in the opcdscs table */
    UINT32 bsadr;           /* base addr vm uses for calculations for addresses
                               of emulated opcodes */
    UINT32 obfus;           /* obfus const used to obfuscate values in the vm
                               structs (UINT8 for obfuscate opcodes, UINT32 for
                               obfuscate addresses) */
    UINT8 permtab[NUM_HNDL];/* handlers permutation table */
    ULONG64 hndls[NUM_HNDL];/* handlers are read from internal struct (dt_acs_t) */
    UINT32 conf_dt_sz;      /* confidential data size */
} vmin_aspr_t;

/* max VM input length */
#define MAX_VMIN        0x60

/* indexes of the vmin_aspr_t fields in
   a version specific vm input structs */
static const size_t ASPR_1_6X_VMIN_OFFS[] = {
    0x04, 0x08, 0x0c, 0x10, (size_t)-1, (size_t)-1, (size_t)-1};
static const size_t ASPR_UNKNOWN_VMIN_OFFS[] = {
    0x04, 0x08, 0x4c, 0x50, 0x0c, 0x20, 0x48};

/* version specific vm input struct lengths */
static const size_t ASPR_1_6X_VMIN_LEN = 0x18;
static const size_t ASPR_UNKNOWN_VMIN_LEN = 0x54;

/* version specific dt_acs_t struct sizes */
static const size_t ASPR_UNKNOWN_DT_ACS_LEN = 0x04;

/* version specific index to access hander in dt_acs_t struct */
static const size_t ASPR_UNKNOWN_DT_ACS_HNDL_OFF = 0;


/* ASPR opcode desc */
typedef struct _opcdsc_aspr_t
{
    /* vm's opcode encoding bytes */
    UINT8 enc_opc_1;    /* main opcode (may be prefix) */
    UINT8 enc_opc_2;    /* main opcode if prefix is present */
    UINT8 enc_opc_3;    /* 0f's escaped opcode */
    UINT32 enc_imm;     /* opcode's immediate oper */
    UINT8 enc_modrm;    /* modrm_byte */
    UINT8 enc_sib;      /* sib byte */
    UINT32 enc_displ;   /* opcode's displacement oper */

    UINT8 b_rel_addr;   /* relative addr flag */
    UINT32 opc_addr;    /* opcode's address */
} opcdsc_aspr_t;

/* max VM opcode encoding */
#define MAX_VMOPC       0x20

/* indexes of the opcdsc_aspr_t fields in
   version specific opcode desc structs */
static const size_t ASPR_1_6X_OPCDSC_OFFS[] = {
    0x01, 0x00, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0e, 0x0f};

/* version specific opcode desc lengths */
static const size_t ASPR_1_6X_OPCDSC_LEN = 0x13;

/* Read ASPR VM input struct from address 'vmin_addr' and write under 'p_vmin'
 */
static BOOL read_vmin(aspr_ver_t ver, ULONG64 vmin_addr, vmin_aspr_t *p_vmin)
{
    BOOL ret=FALSE, b_conf_dt;
    const size_t *vmin_offs;
    size_t vmin_len, dt_acs_len=0, dt_acs_hndl_off=0;

    switch (ver)
    {
    case aspr_unknown:
        b_conf_dt=TRUE;
        vmin_offs = &ASPR_UNKNOWN_VMIN_OFFS[0];
        vmin_len = ASPR_UNKNOWN_VMIN_LEN;
        dt_acs_len = ASPR_UNKNOWN_DT_ACS_LEN;
        dt_acs_hndl_off = ASPR_UNKNOWN_DT_ACS_HNDL_OFF;
        break;

    case aspr_1_6X:
        b_conf_dt=FALSE;
        vmin_offs = &ASPR_1_6X_VMIN_OFFS[0];
        vmin_len = ASPR_1_6X_VMIN_LEN;
        break;

    default:
        goto finish;
    }

    ULONG cb;
    UINT8 vmin_buf[MAX_VMIN];

    if (!(read_memory(vmin_addr, vmin_buf, vmin_len, &cb) && cb==vmin_len))
        goto finish;
    memset(p_vmin, 0, sizeof(*p_vmin));

    p_vmin->opcdscs_addr = DEBUG_EXTEND64(get_32uint_le(&vmin_buf[vmin_offs[0]]));
    p_vmin->n_opcdscs = get_32uint_le(&vmin_buf[vmin_offs[1]]);
    p_vmin->bsadr = get_32uint_le(&vmin_buf[vmin_offs[2]]);
    p_vmin->obfus = get_32uint_le(&vmin_buf[vmin_offs[3]]);

    if (b_conf_dt)
    {
        for (UINT i=0; i < NUM_HNDL; i++)
            p_vmin->permtab[i] = vmin_buf[vmin_offs[4]+i];
        for (UINT i=0; i < NUM_HNDL; i++) {
            p_vmin->hndls[i] = DEBUG_EXTEND64(
                get_32uint_le(&vmin_buf[vmin_offs[5] +
                i*dt_acs_len + dt_acs_hndl_off]));
        }
        p_vmin->conf_dt_sz = get_32uint_le(&vmin_buf[vmin_offs[6]]);
    }

    ret=TRUE;
finish:
    return ret;
}

/* Returns TRUE if 'opc' opcode has mod/rm byte.
   'b_0f_esc' specifies if 'opc' is escaped by 0x0F.
 */
static BOOL is_mod_rm_byte(UINT opc, BOOL b_0f_esc)
{
    /* 1 byte opcode list with mod/rm byte */
    static const UINT8 MOD_RM_OPCS[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b,
        0x10, 0x11, 0x12, 0x13, 0x18, 0x19, 0x1a, 0x1b,
        0x20, 0x21, 0x22, 0x23, 0x28, 0x29, 0x2a, 0x2b,
        0x30, 0x31, 0x32, 0x33, 0x38, 0x39, 0x3a, 0x3b,
        0x62, 0x63, 0x69, 0x6b,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0xc0, 0xc1, 0xc4, 0xc5, 0xc6, 0xc7,
        0xd0, 0xd1, 0xd2, 0xd3,
        0xf6, 0xf7, 0xfe, 0xff
    };

    /* 2 byte opcode (1st 0x0f) with mod/rm byte */
    static const UINT8 MOD_RM_0F_OPCS[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x0d,
        0x1f,
        0x20, 0x21, 0x22, 0x23,
        0xa3, 0xa4, 0xa5, 0xab, 0xac, 0xad, 0xaf,
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6,
        0xb7, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
        0xc0, 0xc1, 0xc7
    };

    const UINT8 *modrm_opcs = MOD_RM_OPCS;
    size_t modrm_opcs_len = ARRAY_SZ(MOD_RM_OPCS);

    if (b_0f_esc) {
        modrm_opcs = MOD_RM_0F_OPCS;
        modrm_opcs_len = ARRAY_SZ(MOD_RM_0F_OPCS);
    }

    size_t j;
    for (j=0; j<modrm_opcs_len; j++) if (opc==modrm_opcs[j]) break;

    return j<modrm_opcs_len;
}

/* Read ASPR VM opcode desc struct from address 'vmin_addr' and write under
   'p_opcdsc'
 */
static BOOL read_opcdsc(aspr_ver_t ver,
    const vmin_aspr_t *p_vmin, ULONG64 opcdsc_addr, opcdsc_aspr_t *p_opcdsc)
{
    BOOL ret=FALSE;
    const size_t *opcdsc_offs=NULL;
    size_t opcdsc_len=0;

    switch (ver)
    {
    case aspr_unknown:
      {
        UINT8 opc1=0;
        for (UINT i=0; i<NUM_HNDL; i++)
        {
            UINT32 call_ret;
            ULONG64 hndl_addr = p_vmin->hndls[p_vmin->permtab[i]];

            if (!call_dt_hndl(hndl_addr, opcdsc_addr, &call_ret)) {
                err_dbgprintf("Can not call handler %d [0x%p] on the target "
                    "machine\n", i, hndl_addr);
                goto err;
            }

            switch (i)
            {
            case 0:
                p_opcdsc->enc_opc_2 = call_ret+p_vmin->obfus;
                break;
            case 1:
                opc1 = call_ret;
                p_opcdsc->enc_opc_1 = call_ret+p_vmin->obfus;
                break;
            case 2:
                p_opcdsc->enc_opc_3 = call_ret+p_vmin->obfus;
                break;
            case 3:
                if (p_opcdsc->enc_imm=call_ret)
                    p_opcdsc->enc_imm += p_vmin->obfus+opc1;
                break;
            case 5:
                p_opcdsc->enc_modrm = call_ret;
                break;
            case 6:
                p_opcdsc->enc_sib = call_ret;
                break;
            case 7:
                p_opcdsc->enc_displ = call_ret;
                break;
            case 8:
                p_opcdsc->b_rel_addr = call_ret;
                break;
            case 9:
                p_opcdsc->opc_addr = call_ret + p_vmin->obfus + p_vmin->bsadr;
                break;
            }
        }
        goto no_err;
      }

    case aspr_1_6X:
        opcdsc_offs = &ASPR_1_6X_OPCDSC_OFFS[0];
        opcdsc_len = ASPR_1_6X_OPCDSC_LEN;
        break;

    default:
        goto err;
    }

    ULONG cb;
    UINT8 opcdsc_buf[MAX_VMOPC];

    if (!(read_memory(opcdsc_addr, opcdsc_buf, opcdsc_len, &cb) &&
        cb==opcdsc_len)) goto err;

    p_opcdsc->enc_opc_1 = opcdsc_buf[opcdsc_offs[0]] + p_vmin->obfus;
    p_opcdsc->enc_opc_2 = opcdsc_buf[opcdsc_offs[1]] + p_vmin->obfus;
    p_opcdsc->enc_opc_3 = opcdsc_buf[opcdsc_offs[2]] + p_vmin->obfus;

    if (p_opcdsc->enc_imm=get_32uint_le(&opcdsc_buf[opcdsc_offs[3]]))
        p_opcdsc->enc_imm += p_vmin->obfus + opcdsc_buf[opcdsc_offs[0]];

    p_opcdsc->enc_modrm = opcdsc_buf[opcdsc_offs[4]];
    p_opcdsc->enc_sib = opcdsc_buf[opcdsc_offs[5]];
    p_opcdsc->enc_displ = get_32uint_le(&opcdsc_buf[opcdsc_offs[6]]);
    p_opcdsc->b_rel_addr = opcdsc_buf[opcdsc_offs[7]];
    p_opcdsc->opc_addr = get_32uint_le(&opcdsc_buf[opcdsc_offs[8]]) +
        p_vmin->obfus + p_vmin->bsadr;

no_err:
    ret=TRUE;
err:
    return ret;
}

/* ASPR VM opcode decoder.
   Addresses of the VM input and decoded opcode are passed by 'vmin_addr' and
   'opcdsc_addr'. 'p_dec_opc' and 'p_addr_opc' will receive decoded opcode bytes
   and an address of the decoded opcode respectively. Returns TRUE on success.
 */
static BOOL decode_vmopc(aspr_ver_t ver, ULONG64 vmin_addr,
    ULONG64 opcdsc_addr, UINT8 *p_dec_opc, UINT32 *p_addr_opc)
{
    BOOL ret=FALSE;

    vmin_aspr_t vmin;
    if (!read_vmin(ver, vmin_addr, &vmin)) goto finish;

    opcdsc_aspr_t opcdsc;
    if (!read_opcdsc(ver, &vmin, opcdsc_addr, &opcdsc));

    *p_addr_opc = opcdsc.opc_addr;

    UINT i=0;
    UINT8 opc = opcdsc.enc_opc_1;

    /* check opcode against prefixes */
    if (opc==0xf0 ||  /* LOCK */
        opc==0xf2 ||  /* REPNE */
        opc==0xf3 ||  /* REP */

        opc==0x2e ||  /* CS */
        opc==0x36 ||  /* SS */
        opc==0x3e ||  /* DS */
        opc==0x26 ||  /* ES */
        opc==0x64 ||  /* FS */
        opc==0x65 ||  /* GS */

        opc==0x66 ||  /* oper size override */
        opc==0x67)    /* addr size override */
    {
        /* write the prefix and read the next opcode byte */
        p_dec_opc[i++] = opc;
        opc = opcdsc.enc_opc_2;
    }

    BOOL b_0f_esc=FALSE, b_modrm=FALSE;

    /* check against 0x0F escape byte */
    if (opc==0x0f)
    {
        /* write esc and read the next opcode byte */
        p_dec_opc[i++] = opc;
        opc = opcdsc.enc_opc_3;
        b_0f_esc = TRUE;
    }

    p_dec_opc[i++] = opc;

    if (is_mod_rm_byte(opc, b_0f_esc))
    {
        /* opc has mod/rm byte, parse it to extract possible sib byte & displ */
        UINT displ_len=0;

        b_modrm=TRUE;
        p_dec_opc[i++] = opcdsc.enc_modrm;

        /* recognize displ */
        switch ((opcdsc.enc_modrm)>>6)
        {
        case 0:
            if ((opcdsc.enc_modrm & 0x07)==5) displ_len=4;
            break;
        case 1:
            displ_len=1;
            break;
        case 2:
            displ_len=4;
            break;
        }

        if ((opcdsc.enc_modrm >> 6)!=3 && (opcdsc.enc_modrm & 0x07)==4)
        {
            /* sib found, write it */
            p_dec_opc[i++] = opcdsc.enc_sib;
            if ((opcdsc.enc_sib & 0x07)==5) displ_len=4;
        }

        /* write mod/rm displ if found */
        if (displ_len>0)
        {
            UINT32 displ = opcdsc.enc_displ;
            if (displ_len==4 && opcdsc.b_rel_addr) displ += vmin.bsadr;
            set_32uint_le(&p_dec_opc[i], displ);

            i+=displ_len;
        }
    }

    /* To avoid complexity of tracking immediate operands and their length for
       specific opcodes, the approach of tracking & decoding such oper is
       slightly different:

      - The immediate oper is always decoded. If it is absent for a specific
        opcode it will be discarded by the disasm as the last part of the whole
        opcode's bytes.
      - The decoded immediate oper length is always 4 bytes. It is no problem
        since oper is little-endianed.
      - The non-conditional branch opcodes (call, jmp, etc) use 'displ oper' as
        their immediate oper. For those opcodes 'imm oper' is set to 0. Therefore:
        if 'imm oper' is 0 and there has been no mod/rm byte write 'displ oper'
        to the output. Otherwise write the zero 'imm oper'. Such approach shall
        guarantee proper disassembly.
     */

    if (opcdsc.enc_imm)
    {
        UINT32 imm = opcdsc.enc_imm;
        if (opcdsc.b_rel_addr) imm += vmin.bsadr;
        set_32uint_le(&p_dec_opc[i], imm);
    } else
    {
        UINT32 displ = (!b_modrm ? opcdsc.enc_displ : 0);
        if (opcdsc.b_rel_addr) displ += vmin.bsadr;
        set_32uint_le(&p_dec_opc[i], displ);
    }

    ret=TRUE;
finish:
    return ret;
}

/* Disassembly VM opcode. Addresses of the VM input and decoded opcode are passed
   by 'vmin_addr' and 'opcdsc_addr'. 'pc_out' will get disassembled opcode string.

   The func calls ver-specific func for decoding vm opcode into intel opcode and
   presents disassembled string on the output.
 */
static void disasm_vmopc(
    aspr_ver_t ver, ULONG64 vmin_addr, ULONG64 opcdsc_addr, char *pc_out)
{
    pc_out[0]=0;

    UINT8 dec_opc[INSN_MAX];
    ULONG64 dec_opc_addr;

    /* decode vm opc */
    UINT32 addr;
    if (!decode_vmopc(ver, vmin_addr, opcdsc_addr, dec_opc, &addr)) goto finish;
    dec_opc_addr = DEBUG_EXTEND64(addr);

    /* ... and disassembly */
    char dasm_out[80];
    size_t dec_opc_sz =
        disasm(dec_opc, dasm_out, sizeof(dasm_out), 32, dec_opc_addr, FALSE, 0);
    if (!dec_opc_sz) goto finish;

    char str_dec_opc[2*sizeof(dec_opc)+1];
    bts2hex(dec_opc, dec_opc_sz, str_dec_opc);

    sprintf(pc_out, "%08x %- 15s %s", (UINT32)dec_opc_addr, str_dec_opc, dasm_out);

finish:
    return;
}

/* ASPR VM input disassembly. The func iterates vm input through its opcodes and
   call disasm_vmopc() on each of them.
 */
static void vm_disasm_aspr(aspr_ver_t ver, ULONG64 vmin_addr)
{
    vmin_aspr_t vmin;
    if (!read_vmin(ver, vmin_addr, &vmin)) goto finish;

    size_t opcdsc_len;
    switch (ver)
    {
    case aspr_unknown:
        opcdsc_len = vmin.conf_dt_sz;
        break;

    case aspr_1_6X:
        opcdsc_len = ASPR_1_6X_OPCDSC_LEN;
        break;

    default:
        goto finish;
    }

    dbgprintf("VM input: 0x%p\n", vmin_addr);

    UINT32 i;
    ULONG64 opcdsc_addr = vmin.opcdscs_addr;

    for (i=0; i<vmin.n_opcdscs; i++, opcdsc_addr+=opcdsc_len)
    {
        char disasm_buf[160];
        disasm_vmopc(ver, vmin_addr, opcdsc_addr, disasm_buf);
        dbgprintf("%s\n", disasm_buf);
    }

finish:
    return;
}

/* Disassembly VM input under the address 'vmin_addr'. Depending on ASPR ver call
   ver-specific disassembly func.
 */
void vm_disasm(ULONG64 vmin_addr)
{
    aspr_ver_t ver = get_version();
    vm_disasm_aspr(ver, vmin_addr);
}

/* ASPR VM context parser.
   Get ASPR VM context written under address 'vmctx_addr' and write the result
   under 'p_vmctx'. Returns TRUE if success.
 */
static BOOL read_vmctx(aspr_ver_t ver, ULONG64 vmctx_addr, vmctx_t *p_vmctx)
{
    BOOL ret=FALSE;
    const size_t *vmctx_offs;
    size_t vmctx_len;

    switch (ver)
    {
    case aspr_unknown:
    case aspr_1_6X:
        vmctx_offs = &ASPR_1_6X_VMCTX_OFFS[0];
        vmctx_len = ASPR_1_6X_VMCTX_LEN;
        break;

    default:
        goto finish;
    }

    ULONG cb;
    UINT8 vmctx_buf[MAX_VMCTX];

    /* read the vm context struct */
    if (!(read_memory(vmctx_addr, vmctx_buf, vmctx_len, &cb) && cb==vmctx_len))
        goto finish;

    p_vmctx->eax = get_32uint_le(&vmctx_buf[vmctx_offs[0]]);
    p_vmctx->ebx = get_32uint_le(&vmctx_buf[vmctx_offs[1]]);
    p_vmctx->ecx = get_32uint_le(&vmctx_buf[vmctx_offs[2]]);
    p_vmctx->edx = get_32uint_le(&vmctx_buf[vmctx_offs[3]]);
    p_vmctx->esi = get_32uint_le(&vmctx_buf[vmctx_offs[4]]);
    p_vmctx->edi = get_32uint_le(&vmctx_buf[vmctx_offs[5]]);
    p_vmctx->ebp = get_32uint_le(&vmctx_buf[vmctx_offs[6]]);
    p_vmctx->esp = get_32uint_le(&vmctx_buf[vmctx_offs[7]]);
    p_vmctx->eip = get_32uint_le(&vmctx_buf[vmctx_offs[8]]);
    p_vmctx->flags = get_32uint_le(&vmctx_buf[vmctx_offs[9]]);
    p_vmctx->opcdsc_addr =
        DEBUG_EXTEND64(get_32uint_le(&vmctx_buf[vmctx_offs[10]]));

    ret=TRUE;
finish:
    return ret;
}

/* Support func for printing ASPR VM context. */
static void print_vmctx_aspr(
    aspr_ver_t ver, ULONG64 vmctx_addr, ULONG64 vmin_addr, DWORD flags)
{
    vmctx_t vmctx;

    if (!read_vmctx(ver, vmctx_addr, &vmctx)) goto finish;

    /* prepare eflags out */
    char flags_buf[56];
    sprintf(flags_buf, "%08x [o%d d%d s%d z%d a%d p%d c%d]",
        vmctx.flags,
        ((vmctx.flags>>11) & 1),
        ((vmctx.flags>>10) & 1),
        ((vmctx.flags>>7) & 1),
        ((vmctx.flags>>6) & 1),
        ((vmctx.flags>>4) & 1),
        ((vmctx.flags>>2) & 1),
        (vmctx.flags & 1));

    UINT32 ref_esp[2];
    ULONG64 esp_addr = DEBUG_EXTEND64(vmctx.esp);
    char ref_esp_buf[24]="???";

    /* prepare deref-esp out */
    ULONG cb;
    if (read_memory(esp_addr, &ref_esp, sizeof(ref_esp), &cb) &&
        cb==sizeof(ref_esp))
    {
        sprintf(ref_esp_buf, "%08x %08x", get_32uint_le(&ref_esp[0]),
            get_32uint_le(&ref_esp[1]));
    }

    char disasm_buf[160];
    *disasm_buf=0;

    if (vmin_addr && vmctx.opcdsc_addr)
    {
        /* if vm input has been set, disasm the current opcode */
        disasm_vmopc(ver, vmin_addr, vmctx.opcdsc_addr, disasm_buf);
    }

    if (flags&PRNCTX_LINE)
    {
        size_t disasm_len = strlen(disasm_buf);

        if (disasm_len>0) {
            size_t i;
            for (i=disasm_len; i<61; i++) disasm_buf[i]=' ';
            disasm_buf[i]=' ';
            disasm_buf[i+1]=0;
        } else {
            /* if no disassembly is present eip info will be needed */
            sprintf(disasm_buf, "eip=%08x ", vmctx.eip);
        }

        dbgprintf(
            "%seax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x "
            "edi=%08x ebp=%08x esp=%08x *esp=[%s] efl=%s\n",
            disasm_buf, vmctx.eax, vmctx.ebx, vmctx.ecx, vmctx.edx, vmctx.esi,
            vmctx.edi, vmctx.ebp, vmctx.esp, ref_esp_buf, flags_buf);
    } else
    {
        dbgprintf(
            "VM context: 0x%p\n"
            "  eip=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x\n"
            "  edi=%08x ebp=%08x esp=%08x *esp=[%s] efl=%s\n",
            vmctx_addr, vmctx.eip, vmctx.eax, vmctx.ebx, vmctx.ecx, vmctx.edx,
            vmctx.esi, vmctx.edi, vmctx.ebp, vmctx.esp, ref_esp_buf, flags_buf);
    }

    if (!(flags&PRNCTX_LINE) && *disasm_buf)
    {
        dbgprintf(
            "VM input: 0x%p\n"
            "  %s\n",
            vmin_addr, disasm_buf);
    }

finish:
    return;
}

/* Print VM context from an address 'vmctx_addr'. If an address of a VM input is
   provided (vmin_addr!=0) the current executed opcode is also displayed.
 */
void print_vmctx(ULONG64 vmctx_addr, ULONG64 vmin_addr, DWORD flags)
{
    aspr_ver_t ver = get_version();
    print_vmctx_aspr(ver, vmctx_addr, vmin_addr, flags);
}

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
#include "oep_aspr.h"
#include "aip_aspr.h"

extern "C" {
#include "disasm/disasm.h"
}

/* max number of traces for OEP recognition before giving up */
#define MAX_TRACES              5000

/* max size of the OEP decryption func body */
#define MAX_OEPDECR_BODY_LEN    0x300

typedef
struct _oep_env_t
{
    UINT32 eip_rva_obf;
    ULONG64 mod_base;
    ULONG64 oep_decr_addr;
} oep_env_t;

/* max env_t struct size */
#define MAX_OEP_ENV             0x50

/* indexes of the oep_env_t fields in version specific oep_env_t structs */
static const size_t ASPR_1_6X_OEPENV_OFFS[] = {0x0c, 0x10, 0x14};

/* version specific oep_env_t struct lengths */
static const size_t ASPR_1_6X_OEPENV_LEN = 0x28;

#define NUM_HNDL           10U

typedef
struct _poly_buf_env_t
{
    ULONG64 mod_base;
    UINT32 n_emuls;
    ULONG64 exe_base;
    UINT8 permtab[NUM_HNDL];
    ULONG64 emuls_addr;
    ULONG64 hndls[NUM_HNDL];
    UINT32 obfus;
    UINT32 conf_dt_sz; 
    UINT32 obfus2;
    BOOL use_obfus2;
} poly_buf_env_t;

/* max poly_buf_env_t struct size */
#define MAX_POLY_BUF_ENV    0x150

/* indexes of the poly_buf_env_t fields in ver. specific poly_buf_env_t structs */
static const size_t ASPR_UNKNOWN_POLY_BUF_ENV_OFFS[] =
    {0x10, 0x14, 0x18, 0x24, 0x30, 0x40, 0x68, 0x6c, 0x70, 0x74};

/* version specific poly_buf_env_t struct lengths */
static const size_t ASPR_UNKNOWN_POLY_BUF_ENV_LEN = 0x100;

/* version specific dt_acs_t struct sizes */
static const size_t ASPR_UNKNOWN_DT_ACS_LEN = 0x04;

/* version specific index to access hander in dt_acs_t struct */
static const size_t ASPR_UNKNOWN_DT_ACS_HNDL_OFF = 0;

typedef enum _tropc_tpy_t
{
    tropc_other=0,
    tropc_jmp_rel8,
    tropc_jmp_rel32,
    tropc_jcc_rel8,
    tropc_jcc_rel32,
    tropc_loop_rel8,        /* loopne/loope/loop */
    tropc_jcxz_rel8,
    tropc_ret,
    tropc_push_imm32,
    tropc_vmopc_call,
    tropc_vmopc_jmp,
    tropc_vmopc_jcc,
    tropc_vmopc_cmp_jcc,
    tropc_vmopc_unknwn
} tropc_tpy_t;

typedef enum _tropc_flgs_t
{
    tropc_flg_revacs=1,     /* reverse access for the next opcode */
    tropc_flg_ref=2         /* opc is referenced by reverse access */
} tropc_flgs_t;

/* traced opcode descr struct */
typedef struct _tropc_t
{
    struct {
        UINT16 tpy:      4; /* tropc_tpy_t values */
        UINT16 flags:    4; /* tropc_flgs_t values */
        UINT16 prefs_sz: 3; /* prefixes size */
        UINT16 opc_sz:   5; /* whole opcode size */
    };
    UINT32 ra;              /* poly buf addr (relative to the poly buf base) */
    union {
        UINT32 cond_ra;     /* conditional branch rel-addr of a conditional opc */
        UINT32 vm_cret_ra;  /* return rel-addr for vm call opcode */
    };
    UINT32 new_ra;          /* repaired relative addr; -1: not set */
} tropc_t;

/* traced opcodes buffer's header */
typedef struct _trbuf_hdr_t
{
    UINT n_elems;           /* elements in the buffer */
    UINT n_capas;           /* capacity of the buffer */
    _trbuf_hdr_t *p_next;   /* next buf in the chain */
    _trbuf_hdr_t *p_prev;   /* prev buf in the chain */
    tropc_t elems[0];       /* elements go after the header */
} trbuf_hdr_t;


/* ASPR oep_env_t struct parser. Get the struct written under address
   'oep_env_addr' and write the result under 'p_env'. Returns TRUE if success.
 */
static BOOL get_oep_env(aspr_ver_t ver, ULONG64 oep_env_addr, oep_env_t *p_env)
{
    BOOL ret=FALSE;
    const size_t *env_offs;
    size_t env_len;

    switch (ver)
    {
    case aspr_1_6X:
        env_offs = &ASPR_1_6X_OEPENV_OFFS[0];
        env_len = ASPR_1_6X_OEPENV_LEN;
        break;

    default:
        goto finish;
    }

    ULONG cb;
    UINT8 env_buf[MAX_OEP_ENV];

    /* read the oep_env_t struct */
    if (!(read_memory(oep_env_addr, env_buf, env_len, &cb) && cb==env_len))
        goto finish;

    p_env->eip_rva_obf = get_32uint_le(&env_buf[env_offs[0]]);
    p_env->mod_base = DEBUG_EXTEND64(get_32uint_le(&env_buf[env_offs[1]]));
    p_env->oep_decr_addr = DEBUG_EXTEND64(get_32uint_le(&env_buf[env_offs[2]]));

    ret=TRUE;
finish:
    return ret;
}

/* Call OEP decryption code and obtain the OEP rva written under 'p_oep_rva'
   if success (TRUE on return).
 */
static BOOL call_decr_oep_hndl(oep_env_t *p_env, UINT32 *p_oep_rva, BOOL dbg)
{
    BOOL ret=FALSE;
    BOOL rest_need=FALSE, trace_err=FALSE;

    ULONG cb, rd_body=0;
    UINT8 org_body[MAX_OEPDECR_BODY_LEN];

    /* reg indexes in the tables */
    enum {
        /* gpr indexes as in gpr_t */
        eip = gpr_max+1,
        efl,
        /* num of regs */
        regs_n
    };

    const char *reg_names[regs_n] = {
        GPR_NAMES[eax], GPR_NAMES[ecx], GPR_NAMES[edx], GPR_NAMES[ebx],
        GPR_NAMES[esp], GPR_NAMES[ebp], GPR_NAMES[esi], GPR_NAMES[edi],
        "eip", "efl"};
    ULONG reg_ids[regs_n];
    DEBUG_VALUE context[regs_n];

    IDebugControl *DebugControl=NULL;
    IDebugRegisters *DebugRegisters=NULL;

    if (get_client()->QueryInterface(
            __uuidof(IDebugControl), (void **)&DebugControl)!=S_OK ||
        get_client()->QueryInterface(
            __uuidof(IDebugRegisters), (void **)&DebugRegisters)!=S_OK)
        goto finish;

    /* save the processor context */
    UINT i;
    for (i=0; i<regs_n; i++) {
        if (DebugRegisters->GetIndexByName(reg_names[i], &reg_ids[i])!=S_OK)
            goto finish;
    }
    if (DebugRegisters->GetValues(regs_n, reg_ids, 0, context)!=S_OK)
        goto finish;

    DEBUG_VALUE esp_r, eip_r;
    /* esp = esp-0x0c (place for 3 32bits params) */
    esp_r = context[esp];
    esp_r.I32 -= 0x0c;
    /* eip on the called proc */
    eip_r.I32 = (UINT32)p_env->oep_decr_addr;
    eip_r.Type = DEBUG_VALUE_INT32;

    if (DebugRegisters->SetValue(reg_ids[esp], &esp_r)!=S_OK) goto finish;
    rest_need=TRUE;
    if (DebugRegisters->SetValue(reg_ids[eip], &eip_r)!=S_OK) goto finish;

    /* pass params on the stack */
    UINT32 call_prms[3];
    set_32uint_le(&call_prms[0], (UINT32)p_env->mod_base);
    set_32uint_le(&call_prms[1], p_env->eip_rva_obf);
    /* don't change esp at the moment of call */
    set_32uint_le(&call_prms[2], (UINT32)esp_r.I32);
    if (!(write_memory(
        DEBUG_EXTEND64(esp_r.I32), call_prms, sizeof(call_prms), &cb) &&
        cb==sizeof(call_prms))) goto finish;

    /* save original the OEP decryption func's body -
       it's changed during the call being the one-shot proc */
    read_memory(p_env->oep_decr_addr, org_body, sizeof(org_body), &rd_body);

    /* trace loop*/
    for (i=0; i<MAX_TRACES; i++)
    {
        /* trace single opcode */
        if (DebugControl->Execute(
            DEBUG_OUTCTL_IGNORE, "t", DEBUG_EXECUTE_NOT_LOGGED)!=S_OK)
        {
            trace_err=TRUE;
            goto finish;
        }

        /* wait for the trace completion */
        if (DebugControl->WaitForEvent(0, INFINITE)!=S_OK) {
            trace_err=TRUE;
            goto finish;
        }

        /* trace until eip gets out of the oep decryption func */
        if (DebugRegisters->GetValue(reg_ids[eip], &eip_r)!=S_OK) {
            trace_err=TRUE;
            goto finish;
        }
        ULONG64 eip_addr = DEBUG_EXTEND64(eip_r.I32);
        if (!(p_env->oep_decr_addr<=eip_addr &&
            eip_addr<=(p_env->oep_decr_addr+MAX_OEPDECR_BODY_LEN))) break;
    }

    if (i<MAX_TRACES)
    {
        if (dbg) info_dbgprintf("Traced %d times before reaching the OEP\n", i);
        *p_oep_rva = (UINT32)(eip_r.I32 - p_env->mod_base);

        ret=TRUE;
    } else
        err_dbgprintf("print_oep_addr() exceeded max number of traces: %d\n",
            MAX_TRACES);

finish:
    BOOL rest_res=TRUE;
    if (rest_need) {
        /* restore the processor context */
        rest_res = (DebugRegisters->SetValues(regs_n, reg_ids, 0, context)==S_OK)
            && rest_res;

        /* ... and the original memory */
        if (rd_body>0) {
            rest_res = (write_memory(p_env->oep_decr_addr, org_body, rd_body,
                &cb) && cb==rd_body) && rest_res;
        }
    }

    if (!rest_res) {
        warn_dbgprintf("print_oep_addr() can not restore original context; "
            "the target application may crash!\n");
    }

    if (DebugControl) DebugControl->Release();
    if (DebugRegisters) DebugRegisters->Release();

    return ret;
}

/* Print OEP address */
void print_oep_addr(ULONG64 oep_env_addr, DWORD flags)
{
    oep_env_t env;
    aspr_ver_t ver = get_version();

    if (!get_oep_env(ver, oep_env_addr, &env)) goto finish;

    UINT32 oep_rva;
    if (call_decr_oep_hndl(&env, &oep_rva, (flags&GETOEP_DUMPEXT ? FALSE : TRUE)))
    {
        if (flags&GETOEP_DUMPEXT) {
            dbgprintf("[optional_header]\nAddressOfEntryPoint = 0x%08X\n",
                oep_rva);
        } else {
            dbgprintf("Original OEP at: 0x%p, RVA: 0x%08X\n",
                env.mod_base+oep_rva, oep_rva);
        }
    }

finish:
    return;
}

/* ASPR poly_buf_env_t struct parser */
static BOOL get_poly_buf_env(
    aspr_ver_t ver, ULONG64 poly_buf_env_addr, poly_buf_env_t *p_env)
{
    BOOL ret=FALSE;
    const size_t *env_offs;
    size_t env_len, dt_acs_len, dt_acs_hndl_off;

    switch (ver)
    {
    case aspr_unknown:
        env_offs = &ASPR_UNKNOWN_POLY_BUF_ENV_OFFS[0];
        env_len = ASPR_UNKNOWN_POLY_BUF_ENV_LEN;
        dt_acs_len = ASPR_UNKNOWN_DT_ACS_LEN;
        dt_acs_hndl_off = ASPR_UNKNOWN_DT_ACS_HNDL_OFF;
        break;

    default:
        goto finish;
    }

    ULONG cb;
    UINT8 env_buf[MAX_POLY_BUF_ENV];

    /* read the poly_buf_env_t struct */
    if (!(read_memory(poly_buf_env_addr, env_buf, env_len, &cb) && cb==env_len))
        goto finish;

    p_env->mod_base = DEBUG_EXTEND64(get_32uint_le(&env_buf[env_offs[0]]));
    p_env->n_emuls = get_32uint_le(&env_buf[env_offs[1]]);
    p_env->exe_base = DEBUG_EXTEND64(get_32uint_le(&env_buf[env_offs[2]]));
    for (UINT i=0; i < NUM_HNDL; i++) p_env->permtab[i] = env_buf[env_offs[3]+i];
    p_env->emuls_addr = DEBUG_EXTEND64(get_32uint_le(&env_buf[env_offs[4]]));
    for (UINT i=0; i < NUM_HNDL; i++) {
        p_env->hndls[i] = DEBUG_EXTEND64(get_32uint_le(&env_buf[env_offs[5] +
            i*dt_acs_len + dt_acs_hndl_off]));
    }
    p_env->obfus = get_32uint_le(&env_buf[env_offs[6]]);
    p_env->conf_dt_sz = get_32uint_le(&env_buf[env_offs[7]]); 
    p_env->obfus2 = get_32uint_le(&env_buf[env_offs[8]]);
    p_env->use_obfus2 = get_32uint_le(&env_buf[env_offs[9]])!=0;

    ret=TRUE;
finish:
    return ret;
}

/* Get emulated codes data from poly_buf_env_t struct pointed by 'p_env'.
   In case of success the func returns allocated array of emul_t elems, one per
   each emulated code. Size of the array is indicated by poly_buf_env_t::n_emuls.
   The caller need to free the buffer.
 */
static BOOL get_emuls_dt(const poly_buf_env_t *p_env, emul_t **pp_emuls)
{
    BOOL ret=FALSE;
    ULONG64 emul_addr = p_env->emuls_addr;

    size_t to_alloc = p_env->n_emuls*sizeof(**pp_emuls);
    *pp_emuls = (emul_t*)malloc(to_alloc);
    emul_t *p_emul = *pp_emuls;
    if (!p_emul) goto finish;

    memset(p_emul, 0, to_alloc);

    for (UINT32 i=0;
        i<p_env->n_emuls;
        i++, emul_addr+=p_env->conf_dt_sz, p_emul++)
    {
        for (UINT j=0; j<NUM_HNDL; j++)
        {
            UINT32 call_ret;
            ULONG64 hndl_addr = p_env->hndls[p_env->permtab[j]];

            if (!call_dt_hndl(hndl_addr, emul_addr, &call_ret)) {
                err_dbgprintf("Can not call handler %d [0x%p] on the target "
                    "machine\n", j, hndl_addr);
                goto finish;
            }

            switch (j)
            {
            case 0:
                /* obfus2 is not used for opc_addr obfuscation */
                p_emul->opc_addr =
                    p_env->exe_base + (UINT32)(call_ret+p_env->obfus);
                break;
            case 1:
              {
                UINT8 opc = call_ret;
                p_emul->opc = (opc==0 ? opc_call :
                              (opc==1 ? opc_jmp :
                              (opc==2 ? opc_jcc :
                              (opc==3 ? opc_cmp_jcc :
                              (opc_t)opc))));
                break;
              }
            case 2:
              {
                UINT32 adr_rel = call_ret + p_env->obfus +
                    (p_env->use_obfus2 ? p_env->obfus2 : 0);
                if (adr_rel!=(DWORD)-1)
                    p_emul->addr = p_env->exe_base + adr_rel;
                break;
              }
            case 3:
                if (p_emul->opc==opc_jmp || p_emul->opc==opc_call) {
                    /* addr relative to the mod base (outside the poly-buf) */
                    if (!p_emul->addr) {
                        p_emul->addr = p_env->mod_base + (UINT32)(call_ret +
                            p_env->obfus + (p_env->use_obfus2 ? p_env->obfus2 : 0));
                    }
                } else
                if (p_emul->opc==opc_jcc || p_emul->opc==opc_cmp_jcc) {
                    p_emul->addr2 = p_env->exe_base + (UINT32)(call_ret +
                        p_env->obfus + (p_env->use_obfus2 ? p_env->obfus2 : 0));
                }
                break;
            case 4:
                p_emul->jcc = (jcc_t)(UINT8)(
                    p_env->use_obfus2 ? call_ret^p_env->obfus2 : call_ret);
                break;
            case 5:
                p_emul->gpr = (gpr_t)(UINT8)call_ret;
                break;
            case 6:
                p_emul->gpr2 = (gpr_t)(UINT8)call_ret;
                break;
            case 7:
                p_emul->imm = call_ret - (p_env->use_obfus2 ? p_env->obfus2 : 0);
                break;
            case 8:
                p_emul->imm2 = call_ret - (p_env->use_obfus2 ? p_env->obfus2 : 0);
                break;
            case 9:
                call_ret = (UINT8)call_ret;
                if (p_env->use_obfus2) {
                    p_emul->atpy = (call_ret==0 ? a1_mem_b :
                                   (call_ret==1 ? a2_mem_b :
                                   (call_ret==2 ? a1_mem_dw :
                                   (call_ret==3 ? a2_mem_dw :
                                   (args_tpy_t)call_ret))));
                } else {
                    p_emul->atpy = (args_tpy_t)call_ret;
                }
                break;
            }
        }
    }

    ret=TRUE;
finish:
    if (!ret && *pp_emuls) { free(*pp_emuls); *pp_emuls=NULL; }
    return ret;
}

/* Get emulated opcode of addr 'opc_addr' from emuls table */
static inline emul_t *get_emul(
    const emul_t *p_emuls, UINT32 n_emuls, ULONG64 opc_addr)
{
    const emul_t *p_emul=NULL;
    for (UINT i=0; i<n_emuls; i++) {
        if (p_emuls[i].opc_addr==opc_addr) {
            p_emul = &p_emuls[i];
            break;
        }
    }
    return (emul_t*)p_emul;
}

/* Print poly-buf emulated opcodes */
void print_poly_buf_emuls(ULONG64 poly_buf_env_addr)
{
    aspr_ver_t ver = get_version();

    poly_buf_env_t env;
    if (!get_poly_buf_env(ver, poly_buf_env_addr, &env)) goto finish;

    emul_t *p_emuls=NULL;
    if (!get_emuls_dt(&env, &p_emuls)) goto finish;

    dbgprintf("%d emulated opcodes:\n", env.n_emuls);

    for (UINT i=0; i<env.n_emuls; i++)
    {
        opc_t opc = p_emuls[i].opc;
        UINT jcc = (UINT)p_emuls[i].jcc;
        const char *pc_jcc = (jcc<=jcc_max ? JCC_NAMES[jcc] : "j??");

        switch (opc)
        {
        case opc_call:
        case opc_jmp:
            dbgprintf("%d. %08X    jmp %08X%s\n", i+1,
                (UINT32)p_emuls[i].opc_addr, (UINT32)p_emuls[i].addr,
                (opc==opc_call ? " -> as call" : ""));
            break;

        case opc_jcc:
          {
            dbgprintf("%d. %08X    %s %08X; jmp %08X\n", i+1,
                (UINT32)p_emuls[i].opc_addr, pc_jcc, (UINT32)p_emuls[i].addr2,
                (UINT32)p_emuls[i].addr);
            break;
          }

        case opc_cmp_jcc:
          {
            char a1[36], a2[36];
            UINT a1_ptr_sz = (p_emuls[i].atpy==a1_mem_dw ? 4 :
                (p_emuls[i].atpy==a1_mem_b ? 1 : 0));
            UINT a2_ptr_sz = (p_emuls[i].atpy==a2_mem_dw ? 4 :
                (p_emuls[i].atpy==a2_mem_b ? 1 : 0));

            cmparg2str(0, p_emuls[i].gpr, p_emuls[i].imm,
                a1_ptr_sz!=0, a1_ptr_sz, a1);
            cmparg2str(0, p_emuls[i].gpr2, p_emuls[i].imm2,
                a2_ptr_sz!=0, a2_ptr_sz, a2);

            dbgprintf("%d. %08X    cmp %s, %s; %s %08X; jmp %08X\n", i+1,
                (UINT32)p_emuls[i].opc_addr, a1, a2, pc_jcc,
                (UINT32)p_emuls[i].addr2, (UINT32)p_emuls[i].addr);

            break;
          }

        default:
            dbgprintf("%d. %08X    ???\n", i+1, (UINT32)p_emuls[i].opc_addr);
            break;
        }
    }

finish:
    if (p_emuls) free(p_emuls);
    return;
}

/* Free traced opcodes buffer chain */
static void free_trbuf(trbuf_hdr_t *p_trbuf)
{
    do {
        trbuf_hdr_t *p_next=p_trbuf->p_next;
        free(p_trbuf);
        p_trbuf = p_next;
    } while (p_trbuf);
}

/* Allocate traced opcodes buffer for 'n_capas' elements */
static trbuf_hdr_t *alloc_trbuf(size_t n_capas)
{
    trbuf_hdr_t *p_trbuf = NULL;
    if (!n_capas) goto finish;

    size_t to_alloc = RNDUP_DW(sizeof(trbuf_hdr_t)+n_capas*sizeof(tropc_t));
    if (!(p_trbuf=(trbuf_hdr_t*)malloc(to_alloc))) goto finish;

    p_trbuf->n_elems = 0;
    p_trbuf->n_capas = n_capas;
    p_trbuf->p_next = NULL;
    p_trbuf->p_prev = NULL;

finish:
    return p_trbuf;
}

typedef enum _rc_addtrbuf_t
{
    addtrbuf_ok=0,
    addtrbuf_revacs,
    addtrbuf_nomem
} rc_addtrbuf_t;

/* Goto element of the traced opcodes buffer */
static trbuf_hdr_t *goto_elem(const trbuf_hdr_t *p_trbuf, UINT *p_elem_i)
{
    UINT i = *p_elem_i;
    while (i>=p_trbuf->n_elems) {
        if (p_trbuf->p_next) {
            p_trbuf=p_trbuf->p_next;
            i-=p_trbuf->n_elems;
        } else {
            i=p_trbuf->n_elems;
            break;
        }
    }

    *p_elem_i = i;
    return (trbuf_hdr_t*)p_trbuf;
}

/* Get total number of elements in the traced opcodes buffer */
static inline UINT get_trbuf_elems_n(const trbuf_hdr_t *p_trbuf) {
    UINT ret=0;
    for (; p_trbuf; p_trbuf=p_trbuf->p_next) ret+=p_trbuf->n_elems;
    return ret;
}

#define TRBUF_ITER_BEGIN(t, i)      \
    for (;;) {                      \
        for (; i<t->n_elems; i++) {

#define TRBUF_ITER_END(t, i)        \
        }                           \
        if (t->p_next) {            \
            t=t->p_next;            \
            i=0;                    \
        } else break;               \
    }

/* Add traced opcode 'p_tropc' to the buffer 'p_trbuf'. 'proc_elem_i'
   specifies index of the first element of the processed procedure.
 */
static rc_addtrbuf_t add_to_trbuf(trbuf_hdr_t *p_trbuf,
    const tropc_t *p_tropc, UINT proc_elem_i, ULONG64 base_addr, BOOL b_disasm)
{
    rc_addtrbuf_t ret=addtrbuf_ok;

    UINT i=proc_elem_i;
    p_trbuf=goto_elem(p_trbuf, &i);

    /* check for the reverse access */
    TRBUF_ITER_BEGIN(p_trbuf, i)
        if (p_trbuf->elems[i].ra==p_tropc->ra)
        {
            /* reverse access found; mark referenced opc with 'tropc_flg_ref' */
            p_trbuf->elems[i].flags |= tropc_flg_ref;

            /* ... and last opc with 'tropc_flg_revacs' flag */
            for (; p_trbuf->p_next; p_trbuf=p_trbuf->p_next);
            if (!p_trbuf->n_elems) p_trbuf=p_trbuf->p_prev;
            p_trbuf->elems[p_trbuf->n_elems-1].flags |= tropc_flg_revacs;

            /* if referenced opc is not reached by a jump
               we need to inform about an extra jump */
            tropc_tpy_t tpy = (tropc_tpy_t)p_trbuf->elems[p_trbuf->n_elems-1].tpy;
            if (b_disasm) {
                if (!(tpy==tropc_jmp_rel8 ||
                    tpy==tropc_jmp_rel32  ||
                    tpy==tropc_vmopc_call ||
                    tpy==tropc_vmopc_jmp  ||
                    tpy==tropc_vmopc_jcc  ||
                    tpy==tropc_vmopc_cmp_jcc))
                {
                    dbgprintf("%- 24c jmp %08X   ; branch return\n", ' ',
                        (UINT32)(base_addr+p_tropc->ra));
                }
            }
            ret=addtrbuf_revacs;
            goto finish;
        }
    TRBUF_ITER_END(p_trbuf, i)

    /* no revere access - add opcode at the buf's tail */
    if (p_trbuf->n_elems+1 > p_trbuf->n_capas)
    {
        /* allocate buf-new element in the chain */
        trbuf_hdr_t *p_new_trbuf = alloc_trbuf(p_trbuf->n_capas);
        if (!p_new_trbuf) {
            ret=addtrbuf_nomem;
            goto finish;
        }

        p_new_trbuf->p_prev = p_trbuf;
        p_trbuf->p_next = p_new_trbuf;

        p_trbuf=p_new_trbuf;
    }

    p_trbuf->elems[p_trbuf->n_elems] = *p_tropc;
    p_trbuf->n_elems++;

finish:
    return ret;
}

/* Count opcodes prefixes */
static UINT count_opc_prefs(const UINT8 *p_buf, size_t buf_len)
{
    UINT cnt=0;
    for (size_t i=0; i<buf_len; i++) {
        if (p_buf[i]==0xf0 ||  /* LOCK */
            p_buf[i]==0xf2 ||  /* REPNE */
            p_buf[i]==0xf3 ||  /* REP */

            p_buf[i]==0x2e ||  /* CS */
            p_buf[i]==0x36 ||  /* SS */
            p_buf[i]==0x3e ||  /* DS */
            p_buf[i]==0x26 ||  /* ES */
            p_buf[i]==0x64 ||  /* FS */
            p_buf[i]==0x65 ||  /* GS */

            p_buf[i]==0x66 ||  /* oper size override */
            p_buf[i]==0x67)    /* addr size override */
        {
            cnt++;
        } else break;
    }
    return cnt;
}

typedef enum _rc_trace_opc_t
{
    trace_opc_ok=0,
    trace_opc_vmopc_err,
    trace_opc_err
} rc_trace_opc_t;

/* Trace poly buf block: from 'start_addr' to the "ret" opcode, reverse access
   detection or 'end_addr' reach. 'proc_elem_i' specifies 1st element of a proc
   owning the traced block. 'base_addr' specifies base of the poly buf, 'p_emuls'
   points to the emulated opcodes table with length 'n_emuls'. Traced opcodes
   are put into buffer pointed by 'p_trbuf'. If 'b_disasm' is TRUE traced disasm
   opcodes are printed.
 */
static rc_trace_opc_t trace_poly_block(ULONG64 base_addr, ULONG64 start_addr,
    ULONG64 end_addr, trbuf_hdr_t *p_trbuf, UINT proc_elem_i,
    const emul_t *p_emuls, UINT32 n_emuls, BOOL b_disasm)
{
#define ADD_AND_PRINT_OPCODE()                                  \
    rc_addtrbuf_t rc=add_to_trbuf(                              \
        p_trbuf, &tropc, proc_elem_i, base_addr, b_disasm);     \
    if (rc==addtrbuf_nomem) { ret=trace_opc_err; goto finish; } \
    else {                                                      \
        if (rc==addtrbuf_revacs) goto break_rd_buf;             \
        if (b_disasm) {                                         \
            dbgprintf("%08X %- 15s %s%s\n",                     \
                (UINT32)opc_addr, opc_hex, dasm_out, vm_opc);   \
        }                                                       \
    }

    rc_trace_opc_t ret=trace_opc_ok;

    ULONG64 rd_addr = start_addr;
    ULONG64 vm_call_ret_addr;   /* ret addr from the vm call */

    /* read the opcodes-buf */
    for (;;)
    {
        size_t buf_off=0;
        const UINT OPC_BUF_LEN = 0x50;
        UINT8 opc_buf[OPC_BUF_LEN+INSN_MAX]; /* INSN_MAX margin for disassembly */

        /* fill the opcodes-buf */
        size_t rd_len = (end_addr>=rd_addr+OPC_BUF_LEN ?
            OPC_BUF_LEN : (size_t)(end_addr-rd_addr));
        if (!rd_len) {
            /* nothing to read; shall never happen */
            goto break_rd_buf;
        }

        ULONG cb;
        if (!(read_memory(rd_addr, opc_buf, rd_len, &cb) && cb==rd_len)) {
            ret=trace_opc_err;
            goto finish;
        }

        tropc_t tropc;
        ULONG64 opc_addr;
        char opc_hex[2*INSN_MAX+1], dasm_out[80], vm_opc[80];
        *opc_hex = *dasm_out = 0;

        /* process opcodes from the buf */
        for (;;)
        {
            memset(&tropc, 0, sizeof(tropc));
            *vm_opc = 0;

            opc_addr = rd_addr+buf_off;
            UINT8 *p_opc_bts = &opc_buf[buf_off];

            size_t opc_sz = disasm(p_opc_bts,
                dasm_out, sizeof(dasm_out), 32, opc_addr, FALSE, 0);

            if (buf_off+opc_sz>rd_len || !opc_sz)
            {
                /* end of buf/error occurred, re-process the last opcode */
                if (!buf_off) {
                    /* opc too long - shall never happen */
                    ret=trace_opc_err;
                    goto finish;
                }
                rd_addr+=buf_off;
                goto break_proc_opc;
            }
            if (b_disasm) bts2hex(p_opc_bts, opc_sz, opc_hex);

            tropc.tpy = tropc_other;
            tropc.flags = 0;

            UINT prefs_sz = count_opc_prefs(p_opc_bts, rd_len-buf_off);
            tropc.prefs_sz = prefs_sz;
            tropc.opc_sz = opc_sz;

            tropc.ra = (UINT32)(opc_addr-base_addr);
            tropc.new_ra = (UINT32)-1;  /* not set at this stage */

            /* check if the opc is the vm opc */
            emul_t *p_emul=get_emul(p_emuls, n_emuls, opc_addr);
            if (p_emul)
            {
                /* vm opcode */
                UINT jcc = (UINT)p_emul->jcc;
                const char *pc_jcc = (jcc<=jcc_max ? JCC_NAMES[jcc] : "j??");

                switch (p_emul->opc)
                {
                case opc_call:
                    tropc.tpy = tropc_vmopc_call;
                    tropc.vm_cret_ra = (UINT32)(vm_call_ret_addr-base_addr);
                    rd_addr = vm_call_ret_addr;

                    if (b_disasm) {
                        sprintf(vm_opc, "   ; jmp %08X -> call %08X; ret to "
                            "%08X", (UINT32)p_emul->addr, (UINT32)p_emul->addr,
                            (UINT32)rd_addr);
                    }
                    goto break_proc_opc;

                case opc_jmp:
                    tropc.tpy = tropc_vmopc_jmp;
                    rd_addr = p_emul->addr;

                    if (b_disasm) {
                        sprintf(vm_opc, "   ; jmp %08X", (UINT32)p_emul->addr);
                    }
                    goto break_proc_opc;

                case opc_jcc:
                    tropc.tpy = tropc_vmopc_jcc;
                    tropc.cond_ra = (UINT32)(p_emul->addr2-base_addr);
                    rd_addr = p_emul->addr;
                    if (jcc>jcc_max) ret=trace_opc_vmopc_err;

                    if (b_disasm) sprintf(vm_opc, "   ; %s %08X; jmp %08X",
                        pc_jcc, (UINT32)p_emul->addr2, (UINT32)p_emul->addr);
                    goto break_proc_opc;

                case opc_cmp_jcc:
                  {
                    tropc.tpy = tropc_vmopc_cmp_jcc;
                    tropc.cond_ra = (UINT32)(p_emul->addr2-base_addr);
                    rd_addr = p_emul->addr;
                    if (jcc>jcc_max) ret=trace_opc_vmopc_err;

                    if (b_disasm) {
                        char a1[36], a2[36];
                        UINT a1_ptr_sz = (p_emul->atpy==a1_mem_dw ? 4 :
                            (p_emul->atpy==a1_mem_b ? 1 : 0));
                        UINT a2_ptr_sz = (p_emul->atpy==a2_mem_dw ? 4 :
                            (p_emul->atpy==a2_mem_b ? 1 : 0));

                        cmparg2str(0, p_emul->gpr, p_emul->imm,
                            a1_ptr_sz!=0, a1_ptr_sz, a1);
                        cmparg2str(0, p_emul->gpr2, p_emul->imm2,
                            a2_ptr_sz!=0, a2_ptr_sz, a2);

                        sprintf(vm_opc, "   ; cmp %s, %s; %s %08X; jmp %08X",
                            a1, a2, pc_jcc, (UINT32)p_emul->addr2,
                            (UINT32)p_emul->addr);
                    }
                    goto break_proc_opc;
                  }

                default:
                    tropc.tpy = tropc_vmopc_unknwn;
                    ret=trace_opc_vmopc_err;
                    buf_off+=opc_sz;

                    if (b_disasm) sprintf(vm_opc, "   ; ???");
                    break;
                }
            } else
            {
                /* ordinal opcode */
                UINT8 opc = p_opc_bts[prefs_sz];
                if ((opc&0xf0)==0x70) {
                    tropc.tpy = tropc_jcc_rel8;
                    tropc.cond_ra = opc_addr+opc_sz +
                        (LONG64)(INT8)p_opc_bts[prefs_sz+1]-base_addr;
                } else
                if (opc==0x0f && (p_opc_bts[prefs_sz+1]&0xf0)==0x80)
                {
                    tropc.tpy = tropc_jcc_rel32;
                    tropc.cond_ra = opc_addr+opc_sz+
                        (LONG64)(INT32)get_32uint_le(&p_opc_bts[prefs_sz+2])-
                        base_addr;
                } else
                {
                    switch (opc)
                    {
                    case 0x68:  /* PUSH imm32 */
                        tropc.tpy = tropc_push_imm32;
                        vm_call_ret_addr =
                            DEBUG_EXTEND64(get_32uint_le(&p_opc_bts[prefs_sz+1]));
                        break;

                    case 0xc2:  /* RET imm16 */
                    case 0xc3:  /* RET */
                      {
                        tropc.tpy = tropc_ret;
                        ADD_AND_PRINT_OPCODE()
                        goto break_rd_buf;
                      }

                    case 0xe9:  /* JMP 32-rel */
                        tropc.tpy = tropc_jmp_rel32;
                        rd_addr = opc_addr+opc_sz+
                            (LONG64)(INT32)get_32uint_le(&p_opc_bts[prefs_sz+1]);
                        goto break_proc_opc;

                    case 0xeb:  /* JMP 8-rel */
                        tropc.tpy = tropc_jmp_rel8;
                        rd_addr = opc_addr+opc_sz+
                            (LONG64)(INT8)p_opc_bts[prefs_sz+1];
                        goto break_proc_opc;

                    case 0xe0:  /* LOOPNE 8-rel */
                    case 0xe1:  /* LOOPE 8-rel */
                    case 0xe2:  /* LOOP 8-rel */
                        tropc.tpy = tropc_loop_rel8;
                        tropc.cond_ra = opc_addr+opc_sz+
                            (LONG64)(INT8)p_opc_bts[prefs_sz+1]-base_addr;
                        break;

                    case 0xe3:  /* JCXZ 8-rel */
                        tropc.tpy = tropc_jcxz_rel8;
                        tropc.cond_ra = opc_addr+opc_sz+
                            (LONG64)(INT8)p_opc_bts[prefs_sz+1]-base_addr;
                        break;
                    }
                }

                buf_off+=opc_sz;
            }
            ADD_AND_PRINT_OPCODE()
        }
break_proc_opc:
        if (tropc.opc_sz) {
            ADD_AND_PRINT_OPCODE()
        }
    }
break_rd_buf:

finish:
    return ret;
}

/* Trace proc from the poly buf along with all its conditional branches;
   starting from 'start_addr'. Parameters as for trace_poly_block().
 */
static rc_trace_opc_t trace_poly_call(ULONG64 base_addr, ULONG64 start_addr,
    ULONG64 end_addr, trbuf_hdr_t *p_trbuf, UINT proc_elem_i,
    const emul_t *p_emuls, UINT32 n_emuls, BOOL b_disasm)
{
#define TRACE_POLY_BLOCK(a)                                \
    rc = trace_poly_block(base_addr, a, end_addr, p_trbuf, \
        proc_elem_i, p_emuls, n_emuls, b_disasm);          \
    if (rc==trace_opc_err) goto finish;                    \
    else if (rc==trace_opc_vmopc_err) b_vmopc_err=TRUE;

    BOOL b_vmopc_err=FALSE;

    /* main proc call */
    rc_trace_opc_t rc;
    TRACE_POLY_BLOCK(start_addr)

    UINT proc_i=proc_elem_i;
    trbuf_hdr_t *p_proc_trbuf = goto_elem(p_trbuf, &proc_i);

    UINT i=proc_i;
    trbuf_hdr_t *p_trbuf1=p_proc_trbuf;

    /* process conditional branches */
    TRBUF_ITER_BEGIN(p_trbuf1, i)
        tropc_tpy_t tpy = (tropc_tpy_t)p_trbuf1->elems[i].tpy;
        if (tpy==tropc_jcc_rel8 ||
            tpy==tropc_jcc_rel32  ||
            tpy==tropc_loop_rel8  ||
            tpy==tropc_jcxz_rel8  ||
            tpy==tropc_vmopc_jcc  ||
            tpy==tropc_vmopc_cmp_jcc)
        {
            UINT j=proc_i;
            trbuf_hdr_t *p_trbuf2=p_proc_trbuf;
            UINT32 cond_ra = p_trbuf1->elems[i].cond_ra;

            /* check if the cond. branch has been already traced */
            BOOL b_cond_found=FALSE;
            TRBUF_ITER_BEGIN(p_trbuf2, j)
                if (cond_ra==p_trbuf2->elems[j].ra) {
                    b_cond_found=TRUE;
                    goto break_search_cond;
                }
            TRBUF_ITER_END(p_trbuf2, j)
break_search_cond:
            if (!b_cond_found) {
                /* cond. branch not found - need to be traced */
                if (b_disasm) dbgprintf("; conditional branch\n");
                TRACE_POLY_BLOCK(base_addr+cond_ra)
            }
        }
    TRBUF_ITER_END(p_trbuf1, i)

finish:
    return (rc==trace_opc_err ? trace_opc_err :
        (b_vmopc_err ? trace_opc_vmopc_err : trace_opc_ok));
}

/*
 */
BOOL trace_poly_buf(ULONG64 poly_buf_env_addr, BOOL b_disasm)
{
    BOOL ret=FALSE;
    trbuf_hdr_t *p_trbuf=NULL;

    IDebugDataSpaces2 *DebugDataSpaces2=NULL;
    if (get_client()->QueryInterface(
        __uuidof(IDebugDataSpaces2), (void **)&DebugDataSpaces2)!=S_OK)
        goto finish;

    aspr_ver_t ver = get_version();

    /* read poly buf and its emuls */
    poly_buf_env_t env;
    if (!get_poly_buf_env(ver, poly_buf_env_addr, &env)) goto finish;

    emul_t *p_emuls=NULL;
    if (!get_emuls_dt(&env, &p_emuls)) goto finish;

    /* recognize poly buf range */
    MEMORY_BASIC_INFORMATION64 vinfo;
    if (DebugDataSpaces2->QueryVirtual(env.exe_base, &vinfo)!=S_OK)
        goto finish;

    size_t n_capas = (3*vinfo.RegionSize)/(2*sizeof(tropc_t));
    ULONG64 end_addr = env.exe_base+vinfo.RegionSize;
    ULONG64 base_addr = env.exe_base;

    if (!(p_trbuf=alloc_trbuf(n_capas))) goto finish;

    if (b_disasm) dbgprintf("; main proc\n");
    if (trace_poly_call(base_addr, base_addr,
        end_addr, p_trbuf, 0, p_emuls, env.n_emuls, TRUE)==trace_opc_err)
            goto finish;
    if (b_disasm) dbgprintf("\n");

    trbuf_hdr_t *p_trbuf1=p_trbuf;
    UINT i=0, main_i=0, main_elems_n=get_trbuf_elems_n(p_trbuf);

    /* process calls loop */
    TRBUF_ITER_BEGIN(p_trbuf1, i)
        if (p_trbuf1->elems[i].tpy==tropc_vmopc_call)
        {
            /* emul must exist (it was previously traced) */
            emul_t *p_emul=get_emul(
                p_emuls, env.n_emuls, base_addr+p_trbuf1->elems[i].ra);

            /* trace calls inside the poly-buf only */
            if (base_addr<=p_emul->addr && p_emul->addr<end_addr)
            {
                UINT j=0;
                BOOL b_call_traced=FALSE;
                trbuf_hdr_t *p_trbuf2=p_trbuf;

                /* check if has not been already traced */
                TRBUF_ITER_BEGIN(p_trbuf2, j)
                    if ((base_addr+p_trbuf2->elems[j].ra)==p_emul->addr) {
                        b_call_traced=TRUE;
                        goto break_search_traced;
                    }
                TRBUF_ITER_END(p_trbuf2, j)
break_search_traced:

                if (!b_call_traced) {
                    if (b_disasm)
                        dbgprintf("; proc_%08X\n", (UINT32)p_emul->addr);
                    if (trace_poly_call(base_addr, p_emul->addr, end_addr,
                        p_trbuf, get_trbuf_elems_n(p_trbuf), p_emuls, env.n_emuls,
                        TRUE) == trace_opc_err)
                    {
                        goto finish;
                    }
                    if (b_disasm) dbgprintf("\n");
                }
            }
        }

        if (++main_i>=main_elems_n) goto break_process_calls;
    TRBUF_ITER_END(p_trbuf1, i)
break_process_calls:

    ret=TRUE;
finish:
    if (p_trbuf) free_trbuf(p_trbuf);
    if (p_emuls) free(p_emuls);
    if (DebugDataSpaces2) DebugDataSpaces2->Release();
    return ret;
}

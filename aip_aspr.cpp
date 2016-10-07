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
#include "aip_aspr.h"
#include <dbghelp.h>    /* MAX_SYM_NAME define */

const char *GPR_NAMES[] =
    {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};

const char *JCC_NAMES[] =
    {"jo", "jno", "jb", "jae", "je", "jne", "jp", "jnp",
     "js", "jns", "jbe", "ja", "jl", "jge", "jle", "jg"};

#define CAPI_DLL            "aspr_capi.dll"

/* AIP call patch size (contains AIP call encoding + 1 extra byte) */
#define AIP_CALL_PT_SZ      6U

/* max emul data size */
#define MAX_EMUL_DT_SZ      0x100U

/* numer of confidential data access handlers */
#define NUM_HNDL            10U

typedef struct _aip_env_t
{
    ULONG64 mem_indxs_addr; /* addr to indexes table for the import
                               seed calculation */
    ULONG64 mod_base;       /* base of the module */
    UINT32 n_ptchs;         /* number of patches */
    UINT32 n_emuls;         /* number of emulated codes (executed after
                               an AIP call) */
    UINT8 prot_tpy;         /* 0: SIP/AIP, 1: eSIP/AIP */
    ULONG64 exe_base;       /* code base addr */
    ULONG64 imports_addr;   /* addr of imports_t struct */
    UINT8 permtab[NUM_HNDL];/* handlers permutation table */
    UINT8 opc_call;         /* CALL */
    UINT8 opc_jmp;          /* JMP */
    UINT8 opc_cmp_jcc;      /* CMP and Jcc */
    UINT8 opc_cmp;          /* CMP */
    UINT8 opc_add;          /* ADD */
    UINT8 opc_mov_rr;       /* MOV reg to reg */
    UINT8 opc_mov_mr;       /* MOV reg to mem */
    UINT8 opc_mov_rdr;      /* MOV reg to *(reg+displ) */
    ULONG64 ptchs_addr;     /* addr to patches table */
    ULONG64 emuls_addr;     /* addr to emulated opcodes table */
    ULONG64 hndls[NUM_HNDL];/* handlers are read from internal struct (dt_acs_t) */
    UINT32 obfus;           /* obfuscation value */
    UINT32 conf_dt_sz;      /* confidential data size */
    ULONG64 ptchs_list_addr;/* pointer to ptchs_list_t struct */
} aip_env_t;

/* max aip_env_t struct size */
#define MAX_AIP_ENV 0x150

/* indexes of the aip_env_t fields in
   version specific aip_env_t structs */
static const size_t ASPR_1_6X_AIP_ENV_OFFS[] =
    {0x10, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x3c, 0x40, 0x4a, 0x4b, 0x4c,
     0x4d, 0x4f, 0x50, 0x51, 0x52, 0x54, 0x58, 0x68, 0xe0, 0xe4, 0x108};

/* version specific aip_env_t struct lengths */
static const size_t ASPR_1_6X_AIP_ENV_LEN = 0x110;

/* version specific dt_acs_t struct sizes */
static const size_t ASPR_1_6X_DT_ACS_LEN = 0x0c;

/* version specific index to access hander in dt_acs_t struct */
static const size_t ASPR_1_6X_DT_ACS_HNDL_OFF = 0;

typedef struct _imports_t
{
    ULONG64 imp_dsc_addr;    /* addr to import description data */
    UINT8 key1[10];          /* decoding key1 */
    UINT8 key2[10];          /* decoding key2 */
    UINT8 imp_endmrk;        /* imp type id: marker of the end of imported procs */
    UINT8 imp_key1_noiat;    /* imp type id: proc name encoded with key1;
                                don't written to the IAT table */
    UINT8 imp_key1_iat;      /* imp type id: proc name encoded with key1;
                                written to the IAT table */
    UINT8 imp_plain;         /* imp type id: proc name in plain text; written
                                to the IAT table */
    UINT8 imp_stl_re;        /* imp type id: stolen import; written to the IAT
                                table as kernel32!RaiseException or its internal
                                impl. */
    UINT8 imp_stl_gpa;       /* 1.6X:
                                  imp type id: stolen import; written to
                                  the IAT table as intern. implementation of
                                  GetProcAddress() with CAPI calls */
                             /* unknown:
                                  Same as imp_stl_gpa2 for 1.6X */
    UINT8 imp_stl_gpa2;      /* 1.6X:
                                  imp type id: resolving proc name encoded with
                                  key1; written to the IAT table as stolen import
                                  calling the resolving proc or CAPI calls */
                             /* unknown:
                                  ASPR versions this id specifies direct import
                                  of the CAPI */
    UINT8 imp_key2_iat;      /* imp type id: proc name encoded with key2;
                                written to the IAT table */
    UINT8 imp_key2_noiat;    /* imp type id: proc name encoded with key2;
                                don't written to the IAT table */
    ULONG64 mod_base;
} imports_t;

/* max imports_t struct size */
#define MAX_IMPS 0x60

/* indexes of the imports_t fields in
   version specific imports_t structs */
static const size_t ASPR_1_6X_IMPS_OFFS[] =
    {0x04, 0x08, 0x12, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x50};

/* version specific imports_t struct lengths */
static const size_t ASPR_1_6X_IMPS_LEN = 0x58;

#define MAX_IDS_FIELD_LEN 0x10

/* indexes of the ids offsets in ids field at
   the beginning of the ASPR imports table desc */
static const size_t ASPR_1_6X_IDS_FIELD_OFFS[] =
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

/* number of ids field length at the beginning of the ASPR imports table desc */
static const size_t ASPR_1_6X_IDS_FIELD_LEN = 9;

/* import patch data */
typedef struct _ptch_t
{
    ULONG64 ptch_addr;      /* addr of a patch */
    opc_t ref_tpy;          /* type of patch reference (call or jmp) */
    union {
        UINT32 emul_id;     /* AIP: if != -1 indicates index in the emul opcodes
                               data table of associated emulation opcode */
        UINT32 imp_spec2b;  /* SIP: import spec. argument 2 for generating
                               import seed */
    };
    UINT32 imp_spec2;
    UINT32 imp_spec1;
    UINT32 imp_spec1b;
    UINT32 lib_id;
    UINT32 proc_id;
    ptch_tpy_t ptch_tpy;
} ptch_t;

/* Call confidential data handler under 'call_addr'. Input for the call is an
   address of the data 'dt_addr'. In case of success the func returns TRUE and
   and sets call return under 'p_ret'.
 */
BOOL call_dt_hndl(ULONG64 call_addr, ULONG64 dt_addr, UINT32 *p_ret)
{
    BOOL ret=FALSE;
    BOOL eax_set=FALSE, esp_set=FALSE, efl_set=FALSE;

    IDebugControl *DebugControl=NULL;
    IDebugRegisters *DebugRegisters=NULL;

    if (get_client()->QueryInterface(
            __uuidof(IDebugControl), (void **)&DebugControl)!=S_OK ||
        get_client()->QueryInterface(
            __uuidof(IDebugRegisters), (void **)&DebugRegisters)!=S_OK)
        goto finish;

    /* read needed regs */
    ULONG regs[4];
    if (DebugRegisters->GetIndexByName("eax", &regs[0])!=S_OK ||
        DebugRegisters->GetIndexByName("efl", &regs[1])!=S_OK ||
        DebugRegisters->GetIndexByName("esp", &regs[2])!=S_OK ||
        DebugRegisters->GetIndexByName("eip", &regs[3])!=S_OK) goto finish;

    DEBUG_VALUE vals[ARRAY_SZ(regs)];
    if (DebugRegisters->GetValues(ARRAY_SZ(regs), regs, 0, vals)!=S_OK)
        goto finish;

    /* eax=dt_addr (input arg)
       esp = esp-4 (place for ret addr) */
    DEBUG_VALUE eax_r;
    eax_r.I32 = (UINT32)dt_addr;
    eax_r.Type = DEBUG_VALUE_INT32;
    DEBUG_VALUE esp_r;
    esp_r = vals[2];
    esp_r.I32 -= 4;

    if (DebugRegisters->SetValue(regs[0], &eax_r)!=S_OK) goto finish;
    eax_set=TRUE;
    if (DebugRegisters->SetValue(regs[2], &esp_r)!=S_OK) goto finish;
    esp_set=TRUE;

    /* *esp = eip (set ret addr) */
    ULONG cb;
    char eip_bf[4];
    set_32uint_le(eip_bf, vals[3].I32);
    if (!(write_memory(DEBUG_EXTEND64(esp_r.I32), eip_bf, sizeof(eip_bf),  &cb)
        && cb==sizeof(eip_bf))) goto finish;

    /* exec 'call call_addr' */
    char cmd[32];
    sprintf(cmd, "g =0x%X 0x%X", (UINT32)call_addr, vals[3].I32);
    if (DebugControl->Execute(
        DEBUG_OUTCTL_IGNORE, cmd, DEBUG_EXECUTE_NOT_LOGGED)!=S_OK) goto finish;

    /* wait for the call completion */
    if (DebugControl->WaitForEvent(0, INFINITE)!=S_OK) goto finish;
    esp_set=FALSE; efl_set=TRUE;

    /* save return code */
    ret = (DebugRegisters->GetValue(regs[0], &eax_r)==S_OK);
    *p_ret = eax_r.I32;

finish:
    BOOL rest_res=TRUE;
    if (eax_set) rest_res =
        (DebugRegisters->SetValue(regs[0], &vals[0])==S_OK) && rest_res;
    if (efl_set) rest_res =
        (DebugRegisters->SetValue(regs[1], &vals[1])==S_OK) && rest_res;
    if (esp_set) rest_res =
        (DebugRegisters->SetValue(regs[2], &vals[2])==S_OK) && rest_res;

    if (!rest_res) warn_dbgprintf("call_dt_hndl() can not restore original "
        "processor context; the target application may crash!\n");

    if (DebugControl) DebugControl->Release();
    if (DebugRegisters) DebugRegisters->Release();

    return ret;
}

/* Decodes data under 'dt' with size 'dt_sz' with a key 'key' (of 'key_sz' size).
   Decoded data will be written under 'dt'.
 */
inline static void decode(UINT8 *dt, UINT32 dt_sz, const UINT8 *key, UINT key_sz)
{
    for (UINT32 i=0; i<dt_sz;) {
        UINT32 to_proc = (dt_sz<key_sz ? dt_sz : key_sz);
        for (UINT32 j=0; j<to_proc; j++) dt[i++] ^= key[j];
    }
}

/* ASPR aip_env_t struct context parser. Get the struct written under address
   'aip_env_addr' and write the result under 'p_env'. Returns TRUE if success.
 */
static BOOL get_aip_env(aspr_ver_t ver, ULONG64 aip_env_addr, aip_env_t *p_env)
{
    BOOL ret=FALSE;
    const size_t *env_offs;
    size_t dt_acs_hndl_off, env_len, dt_acs_len;

    switch (ver)
    {
    case aspr_unknown:
    case aspr_1_6X:
        env_offs = &ASPR_1_6X_AIP_ENV_OFFS[0];
        env_len = ASPR_1_6X_AIP_ENV_LEN;
        dt_acs_hndl_off = ASPR_1_6X_DT_ACS_HNDL_OFF;
        dt_acs_len = ASPR_1_6X_DT_ACS_LEN;
        break;

    default:
        goto finish;
    }

    ULONG cb;
    UINT8 env_buf[MAX_AIP_ENV];

    /* read the aip_env_t struct */
    if (!(read_memory(aip_env_addr, env_buf, env_len, &cb) && cb==env_len))
        goto finish;

    p_env->mem_indxs_addr = DEBUG_EXTEND64(get_32uint_le(&env_buf[env_offs[0]]));
    p_env->mod_base = DEBUG_EXTEND64(get_32uint_le(&env_buf[env_offs[1]]));
    p_env->n_ptchs = get_32uint_le(&env_buf[env_offs[2]]);
    p_env->n_emuls = get_32uint_le(&env_buf[env_offs[3]]);
    p_env->prot_tpy = env_buf[env_offs[4]];
    p_env->exe_base = DEBUG_EXTEND64(get_32uint_le(&env_buf[env_offs[5]]));
    p_env->imports_addr = DEBUG_EXTEND64(get_32uint_le(&env_buf[env_offs[6]]));
    for (UINT i=0; i < NUM_HNDL; i++) p_env->permtab[i] = env_buf[env_offs[7]+i];
    p_env->opc_call = env_buf[env_offs[8]];
    p_env->opc_jmp = env_buf[env_offs[9]];
    p_env->opc_cmp_jcc = env_buf[env_offs[10]];
    p_env->opc_cmp = env_buf[env_offs[11]];
    p_env->opc_add = env_buf[env_offs[12]];
    p_env->opc_mov_rr = env_buf[env_offs[13]];
    p_env->opc_mov_mr = env_buf[env_offs[14]];
    p_env->opc_mov_rdr = env_buf[env_offs[15]];
    p_env->ptchs_addr = DEBUG_EXTEND64(get_32uint_le(&env_buf[env_offs[16]]));
    p_env->emuls_addr = DEBUG_EXTEND64(get_32uint_le(&env_buf[env_offs[17]]));
    for (UINT i=0; i < NUM_HNDL; i++) {
        p_env->hndls[i] =
            DEBUG_EXTEND64(get_32uint_le(&env_buf[env_offs[18] + i*dt_acs_len +
                dt_acs_hndl_off]));
    }
    p_env->obfus = get_32uint_le(&env_buf[env_offs[19]]);
    p_env->conf_dt_sz = get_32uint_le(&env_buf[env_offs[20]]);
    p_env->ptchs_list_addr = DEBUG_EXTEND64(get_32uint_le(&env_buf[env_offs[21]]));

    ret=TRUE;
finish:
    return ret;
}

/* ASPR imports_t struct parser. Get the struct written under address 'imps_addr'
   and write the result under 'p_imps'. Returns TRUE if success.
 */
static BOOL get_imps(aspr_ver_t ver, ULONG64 imps_addr,
    imports_t *p_imps, size_t *p_ids_fld_len, BOOL b_use_imps_ids)
{
    BOOL ret=FALSE;
    const size_t *imps_offs, *ids_fld_offs;
    size_t imps_len;

    switch (ver)
    {
    case aspr_unknown:
    case aspr_1_6X:
        imps_offs = &ASPR_1_6X_IMPS_OFFS[0];
        imps_len = ASPR_1_6X_IMPS_LEN;
        ids_fld_offs = &ASPR_1_6X_IDS_FIELD_OFFS[0];
        *p_ids_fld_len = ASPR_1_6X_IDS_FIELD_LEN;
        break;

    default:
        *p_ids_fld_len=0;
        goto finish;
    }

    ULONG cb;
    UINT8 imps_buf[MAX_IMPS];

    /* read the imports_t struct */
    if (!(read_memory(imps_addr, imps_buf, imps_len, &cb) && cb==imps_len))
        goto finish;

    p_imps->imp_dsc_addr = DEBUG_EXTEND64(get_32uint_le(&imps_buf[imps_offs[0]]));
    memcpy(p_imps->key1, &imps_buf[imps_offs[1]], sizeof(p_imps->key1));
    memcpy(p_imps->key2, &imps_buf[imps_offs[2]], sizeof(p_imps->key2));
    if (b_use_imps_ids)
    {
        /* use ids from imports_t struct */
        p_imps->imp_endmrk = imps_buf[imps_offs[3]];
        p_imps->imp_key1_noiat = imps_buf[imps_offs[4]];
        p_imps->imp_key1_iat = imps_buf[imps_offs[5]];
        p_imps->imp_plain = imps_buf[imps_offs[6]];
        p_imps->imp_stl_re = imps_buf[imps_offs[7]];
        p_imps->imp_stl_gpa = imps_buf[imps_offs[8]];
        p_imps->imp_stl_gpa2 = imps_buf[imps_offs[9]];
        p_imps->imp_key2_iat = imps_buf[imps_offs[10]];
        p_imps->imp_key2_noiat = imps_buf[imps_offs[11]];
    } else
    {
        /* use ids from imports_t::imp_dsc table since
           imports_t may not have been yet fully initialized */
        UINT8 ids_fld[MAX_IDS_FIELD_LEN];
        if (!(read_memory(p_imps->imp_dsc_addr, ids_fld, *p_ids_fld_len, &cb) &&
            cb==*p_ids_fld_len)) goto finish;

        p_imps->imp_endmrk = ids_fld[ids_fld_offs[0]];
        p_imps->imp_key1_noiat = ids_fld[ids_fld_offs[1]];
        p_imps->imp_key1_iat = ids_fld[ids_fld_offs[2]];
        p_imps->imp_plain = ids_fld[ids_fld_offs[3]];
        p_imps->imp_stl_re = ids_fld[ids_fld_offs[4]];
        p_imps->imp_stl_gpa = ids_fld[ids_fld_offs[5]];
        p_imps->imp_stl_gpa2 = ids_fld[ids_fld_offs[6]];
        p_imps->imp_key2_iat = ids_fld[ids_fld_offs[7]];
        p_imps->imp_key2_noiat = ids_fld[ids_fld_offs[8]];
    }
    p_imps->mod_base = DEBUG_EXTEND64(get_32uint_le(&imps_buf[imps_offs[12]]));

    ret=TRUE;
finish:
    return ret;
}

/* Calculate checksum of 'len' bytes from buffer pointed by 'p_in' */
static UINT32 checksum(const UINT8 *p_in, size_t len, UINT32 ivt)
{
    register UINT32 csum=ivt;

    if (len) {
        csum=~csum;
        for (size_t i=len; i; i--) {
            csum ^= ((UINT32)p_in[i-1])<<24;
            for (UINT j=0; j<8; j++) {
                register UINT32 csum_shl = csum<<1;
                csum = ((INT32)csum<0 ? csum_shl^0xDB710641 : csum_shl);
            }
        }
        csum=~csum;
    }
    return csum;
}

/* Generate the import seed value. 'chk_mem_addr' points to memory location used
    to checksum calculation on it. 'len' and 'beg_off' are import specific params:
    imp_spec1 and imp_spec2 taken from the ptch_t struct.
 */
static BOOL gen_imp_seed(const aip_env_t *p_env,
    ULONG64 chk_mem_addr, UINT32 len, UINT32 beg_off, UINT32 *p_csum)
{
    BOOL ret=FALSE;

    UINT8 *p_buf = (UINT8*)malloc(len);
    if (!p_buf) goto finish;

    ULONG cb;
    ULONG64 beg_addr = chk_mem_addr+beg_off;
    ULONG64 end_addr = beg_addr+len;

    if (!(read_memory(beg_addr, p_buf, len, &cb) && cb==len)) goto finish;

    *p_csum=0;

    UINT32 off_i=0;
    ULONG64 prcss_addr=beg_addr;

    for (ULONG64 off_i_addr=p_env->mem_indxs_addr;; off_i_addr+=sizeof(off_i))
    {
        if (!(read_memory(off_i_addr, &off_i, sizeof(off_i), &cb) &&
            cb==sizeof(off_i))) goto finish;
        off_i = get_32uint_le(&off_i);

        /* process until zero'ed offset read from mem_indxs table */
        if (!off_i) break;

        ULONG64 addr_i = chk_mem_addr+off_i;

        if (prcss_addr<=addr_i && addr_i<end_addr) {
            *p_csum = checksum(p_buf+(size_t)(prcss_addr-beg_addr),
                (size_t)(addr_i-prcss_addr), *p_csum);
            prcss_addr = addr_i+4;
        } else
        if (end_addr<=addr_i) break;
    }

    if (end_addr<prcss_addr) {
        err_dbgprintf("Unexpected error in gen_imp_seed()\n");
        goto finish;
    }
    *p_csum = checksum(p_buf+(size_t)(prcss_addr-beg_addr),
        (size_t)(end_addr-prcss_addr), *p_csum);

    ret=TRUE;
finish:
    if (p_buf) free(p_buf);
    return ret;
}

/* Get import patches data from aip_env_t struct pointed by 'p_env'. In case of
   success the func returns allocated array of ptch_t elems, one per each patch.
   Size of the array is indicated by aip_env_t::n_ptchs. The caller need to
   free the buffer. 'chk_mem_addr' is an address of memory used to generate the
   import seed (as partial checksum of some range of the memory staring from
   this address).
 */
static BOOL get_ptchs_dt(
    const aip_env_t *p_env, ULONG64 chk_mem_addr, ptch_t **pp_ptchs)
{
    BOOL ret=FALSE;
    ULONG64 ptch_addr = p_env->ptchs_addr;

    *pp_ptchs = (ptch_t*)malloc(p_env->n_ptchs*sizeof(**pp_ptchs));
    ptch_t *p_ptch = *pp_ptchs;
    if (!p_ptch) goto finish;

    for (UINT32 i=0, obfus=p_env->obfus;
        i < p_env->n_ptchs;
        i++, ptch_addr+=p_env->conf_dt_sz, p_ptch++)
    {
        UINT8 ref_tpy;
        UINT32 imp_seed;

        for (UINT j=0; j<NUM_HNDL; j++)
        {
            /* handler no. 4 is not used for the patch data */
            if (j==4) continue;

            UINT32 call_ret;
            ULONG64 hndl_addr = p_env->hndls[p_env->permtab[j]];

            if (!call_dt_hndl(hndl_addr, ptch_addr, &call_ret)) {
                err_dbgprintf("Can not call handler %d [0x%p] on the target "
                    "machine\n", j, hndl_addr);
                goto finish;
            }

            switch (j)
            {
            case 0:
                p_ptch->ptch_addr =
                    p_env->exe_base + (UINT32)(call_ret + p_env->obfus);
                break;
            case 1:
                ref_tpy = (UINT8)call_ret;
                break;
            case 2:
                p_ptch->emul_id = (UINT32)(call_ret + p_env->obfus);
                break;
            case 3:
                p_ptch->imp_spec2 = (UINT32)(call_ret + p_env->obfus);
                break;
            case 5:
                p_ptch->imp_spec1 = (UINT8)call_ret + 0xff;
                break;
            case 6:
                p_ptch->imp_spec1b = (UINT8)call_ret + 0xff;
            case 7:
                p_ptch->lib_id = call_ret;
                break;
            case 8:
                p_ptch->proc_id = call_ret;
                break;
            case 9:
                {
                    BOOL is_sip = (((UINT8)call_ret)!=1 ? FALSE : TRUE);
                    p_ptch->ptch_tpy = (p_env->prot_tpy==0 ?
                        (is_sip ? ptch_sip : ptch_aip) :
                        (is_sip ? ptch_esip : ptch_aip));
                }
                break;
            }
        }

        /* depending on the patch type calculate the import seed */
        if (!gen_imp_seed(p_env, chk_mem_addr,
                (p_ptch->ptch_tpy==ptch_aip ?
                    p_ptch->imp_spec1 : p_ptch->imp_spec1b),
                (p_ptch->ptch_tpy==ptch_aip ?
                    p_ptch->imp_spec2 : p_ptch->imp_spec2b),
                &imp_seed))
        {
            err_dbgprintf("Unable to calculate import seed value\n");
            goto finish;
        }

        /* ... the lib & proc ids */
        switch (p_ptch->ptch_tpy)
        {
        case ptch_sip:
            p_ptch->lib_id = (UINT16)(p_ptch->lib_id + obfus + imp_seed);
            p_ptch->proc_id = (UINT16)(p_ptch->proc_id - obfus - imp_seed);

            obfus = p_ptch->imp_spec2;
            break;

        case ptch_aip:
            p_ptch->lib_id = (UINT16)(p_ptch->lib_id + imp_seed);
            /* 0xe8: 'call' mnemonic opc */
            p_ptch->proc_id = (UINT16)(p_ptch->proc_id - imp_seed + 0xe8);
            break;

        case ptch_esip:
            p_ptch->lib_id =
                (UINT16)(p_ptch->lib_id + p_ptch->imp_spec2 + imp_seed);
            p_ptch->proc_id =
                (UINT16)(p_ptch->proc_id - p_ptch->imp_spec2 - imp_seed);
            break;
        }

        /* ... and the reference type (eSIP) */
        if (p_ptch->ptch_tpy==ptch_esip) {
            UINT32 is = p_ptch->imp_spec2;
            is = (is>>16)+is;
            is = (is&0xff)-((is>>8)&0xff);

            ref_tpy = (UINT8)(ref_tpy+is);
        }

        /* verify the reference type */
        if (ref_tpy==p_env->opc_call) p_ptch->ref_tpy = opc_call;
        else
        if (ref_tpy==p_env->opc_jmp) p_ptch->ref_tpy = opc_jmp;
        else {
            warn_dbgprintf("Unknown reference type 0x%02X for patch lib id: "
                "0x%04X, proc id: 0x%04X; CALL assumed\n",
                (UINT32)ref_tpy, p_ptch->lib_id, p_ptch->proc_id);

            p_ptch->ref_tpy = opc_call;
        }
    }

    ret=TRUE;
finish:
    if (!ret && *pp_ptchs) { free(*pp_ptchs); *pp_ptchs=NULL; }
    return ret;
}

/* Get emulated codes data from aip_env_t struct pointed by 'p_env'.
   In case of success the func returns allocated array of emul_t elems, one
   per each emulated code. Size of the array is indicated by aip_env_t::n_emuls.
   The caller need to free the buf. The func doesn't set emul_t::opc_addr. It
   shall be set basing on the patch data corresponding to the emuls.
 */
static BOOL get_emuls_dt(const aip_env_t *p_env, emul_t **pp_emuls)
{
    BOOL ret=FALSE;
    ULONG64 emul_addr = p_env->emuls_addr;
    BOOL rest_emul0=FALSE;

    *pp_emuls=NULL;

    if (MAX_EMUL_DT_SZ < p_env->conf_dt_sz) {
        err_dbgprintf(
            "Confidential data size too long: 0x%04X\n", p_env->conf_dt_sz);
        goto finish;
    }

    /* prepare decoding key */
    UINT8 dec_key[0x10];
    for (UINT i=0; i<sizeof(dec_key); i++) dec_key[i]=i+1;
    set_32uint_le(dec_key, p_env->obfus);

    size_t to_alloc = p_env->n_emuls*sizeof(**pp_emuls);
    *pp_emuls = (emul_t*)malloc(to_alloc);
    emul_t *p_emul = *pp_emuls;
    if (!p_emul) goto finish;

    memset(p_emul, 0, to_alloc);

    /* To call access handlers on the target machine there is a need to decode
       emul opcode data and store it in the target's memory, emul no.0 opcode
       data's space is utilized for this case. It is restored after the use */

    ULONG cb;
    UINT8 emul0[MAX_EMUL_DT_SZ];
    ULONG64 emul0_addr = emul_addr;

    for (UINT32 i=0;
        i < p_env->n_emuls;
        i++, emul_addr+=p_env->conf_dt_sz, p_emul++)
    {
        UINT8 emul[MAX_EMUL_DT_SZ];

        if (!(read_memory(emul_addr, emul, p_env->conf_dt_sz, &cb) &&
            cb==p_env->conf_dt_sz)) goto finish;

        if (i==0) memcpy(emul0, emul, p_env->conf_dt_sz);

        decode(emul, p_env->conf_dt_sz, dec_key, sizeof(dec_key));

        if (!(write_memory(emul0_addr, emul, p_env->conf_dt_sz, &cb) &&
            cb==p_env->conf_dt_sz)) goto finish;
        else rest_emul0=TRUE;

        /* handler no. 0 is not used for the emul opcode data */
        for (UINT j=1; j<NUM_HNDL; j++)
        {
            UINT32 call_ret;
            ULONG64 hndl_addr = p_env->hndls[p_env->permtab[j]];

            if (!call_dt_hndl(hndl_addr, emul0_addr, &call_ret)) {
                err_dbgprintf("Can not call handler %d [0x%p] on the target "
                    "machine\n", j, hndl_addr);
                goto finish;
            }

            switch (j)
            {
            case 1:
                {
                    UINT8 opc = call_ret;
                    p_emul->opc = (opc==p_env->opc_call ? opc_call :
                                  (opc==p_env->opc_jmp ? opc_jmp :
                                  (opc==p_env->opc_cmp_jcc ? opc_cmp_jcc :
                                  (opc==p_env->opc_cmp ? opc_cmp :
                                  (opc==p_env->opc_add ? opc_add :
                                  (opc==p_env->opc_mov_rr ? opc_mov_rr :
                                  (opc==p_env->opc_mov_mr ? opc_mov_mr :
                                  (opc==p_env->opc_mov_rdr ? opc_mov_rdr :
                                  (opc_t)opc))))))));
                }
                break;
            case 2:
                p_emul->ptch_sz = (UINT32)(call_ret + p_env->obfus);
                break;
            case 3:
                p_emul->addr =
                    p_env->mod_base + (UINT32)(call_ret + p_env->obfus);
                break;
            case 4:
                p_emul->jcc = (jcc_t)(UINT8)call_ret;
                break;
            case 5:
                p_emul->gpr = (gpr_t)(UINT8)call_ret;
                break;
            case 6:
                p_emul->gpr2 = (gpr_t)(UINT8)call_ret;
                break;
            case 7:
                p_emul->imm = call_ret;
                break;
            case 8:
                p_emul->imm2 = call_ret;
                break;
            case 9:
                /* values increased by 2 */
                p_emul->atpy = (args_tpy_t)(UINT8)(call_ret-2);
                break;
            }
        }
    }

    ret=TRUE;
finish:
    /* restore emul 0 space */
    if (rest_emul0) {
        if (!(write_memory(emul0_addr, emul0, p_env->conf_dt_sz, &cb) &&
            cb==p_env->conf_dt_sz))
        {
            warn_dbgprintf("get_emuls_dt() can not restore original memory "
                "space; the target application may crash!\n");
        }
    }
    if (!ret && *pp_emuls) { free(*pp_emuls); *pp_emuls=NULL; }
    return ret;
}

/* Get non-zero size of 'arg' (in bytes) */
static inline UINT get_nonzero_sz(UINT32 arg)
{
    UINT sz;

    UINT32 abs = ((arg>>31)&1 ? (UINT32)(-arg) : arg);
    for (sz=0; abs; sz++) abs = abs>>8;
    return sz;
}

/* Translates displacement opcodes (JMP/CALL/Jcc) into machine code and writes
   result under 'p_opc'. Number of written bytes is returned. 'opc_addr' is the
   translated opcode address. The func handles opcodes of the following types:
   opc_call, opc_jmp, opc_cmp_jcc.
 */
UINT trans_opc_displ(const emul_t *p_emul, UINT32 opc_addr, UINT8 *p_opc)
{
    static const UINT8 JCC_1B_OPC[] = {
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x7a, 0x7b,
        0x78, 0x79, 0x76, 0x77, 0x7c, 0x7d, 0x7e, 0x7f
    };
    static const UINT8 JCC_2B_OPC[] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x8a, 0x8b,
        0x88, 0x89, 0x86, 0x87, 0x8c, 0x8d, 0x8e, 0x8f
    };

    UINT i=0;

    UINT32 sp = p_emul->ptch_sz-AIP_CALL_PT_SZ;
    if (sp<2 || sp>MAX_AIP_OPC) goto finish;

    opc_t opc = p_emul->opc;
    UINT displ_sz;
    UINT opc_sz = 1;
    sp--;   /* 1: opcode byte */

    if (sp<=3) displ_sz=1;
    else
    if (opc==opc_cmp_jcc && sp==4) displ_sz=1;
    else {
        displ_sz=4;
        if (opc==opc_cmp_jcc) { opc_sz++; sp--; }
    }

    UINT32 rel_addr = (UINT32)p_emul->addr - (UINT32)(opc_addr+opc_sz+displ_sz);
    if (get_nonzero_sz(rel_addr) > displ_sz) goto finish;

    switch (displ_sz)
    {
    /* rel8 */
    case 1:
        if (opc==opc_call) goto finish;

        p_opc[i++] = (opc==opc_jmp ? 0xeb : JCC_1B_OPC[p_emul->jcc]);
        p_opc[i++] = (UINT8)rel_addr;
        break;

    /* rel32 */
    case 4:
        p_opc[i++] = (opc==opc_call ? 0xe8 : (opc==opc_jmp ? 0xe9 : 0x0f));
        if (opc==opc_cmp_jcc) p_opc[i++] = JCC_2B_OPC[p_emul->jcc];
        set_32uint_le(p_opc+i, rel_addr);
        i+=4;
        break;
    }

finish:
    return i;
}

/* Support routine for group 1 opcode translation */
static UINT trans_grp1_opc(UINT8 opc_eax,
    UINT opc_grp1, UINT32 imm, gpr_t gpr, UINT sp, UINT8 *p_opc, BOOL b_expnd)
{
    UINT i=0;

    if (sp<3 || sp>MAX_AIP_OPC) goto finish;

    UINT isz = (get_nonzero_sz(imm)<=1 ? 1 : 4);
    UINT opc_sz = 2;
    if (gpr==eax && isz==4) opc_sz--;   /* 1 opc + ModR/M (optional) */

    if (sp < opc_sz+isz) goto finish;
    sp -= opc_sz+isz;

    if (b_expnd) {
        /* try to consume the extra bytes */
        if (sp>=3 && isz==1) { isz=4; sp-=3; }
        if (sp>=1 && opc_sz==1) { opc_sz++; sp--; }
    }

    if (opc_sz==1) {
        /* for eax operand only */
        p_opc[i++] = opc_eax;
    } else {
        /* ModR/M encoding */
        p_opc[i++] = (isz==1 ? 0x83 : 0x81);
        p_opc[i++] = 0xc0 | (UINT8)(opc_grp1<<3) | (UINT8)gpr;
    }

    if (isz==1) p_opc[i++] = (UINT8)imm;
    else {
        set_32uint_le(p_opc+i, imm);
        i+=4;
    }

finish:
    return i;
}

/* Support routine for opcode with [base+displ] translation */
static UINT trans_opc_mem_rd(UINT8 opc, gpr_t base_gpr,
    UINT32 displ, UINT reg_opc, UINT sp, UINT8 *p_opc, BOOL b_expnd)
{
    UINT i=0;

    if (sp<2 || sp>MAX_AIP_OPC) goto finish;

    UINT dsz = get_nonzero_sz(displ);
    if (dsz>1) dsz=4;
    /* [ebp] can be encoded with a displ only */
    if (dsz==0 && base_gpr==ebp) dsz=1;
    /* 1 opc + 1 ModR/M + 1 SIB for [esp+displ] access */
    UINT opc_sz = (base_gpr==esp ? 3 : 2);

    if (sp < opc_sz+dsz) goto finish;
    sp -= opc_sz+dsz;

    if (b_expnd) {
        /* try to consume the extra bytes */
        if (sp>=4 && dsz==0) { dsz=4; sp-=4; }
        if (sp>=3 && dsz==1) { dsz=4; sp-=3; }
        if (sp>=1 && dsz==0) { dsz=1; sp--; }
        /* alternative SIB encoding */
        /* if (sp>=1 && opc_sz==2) { opc_sz=3; sp--; } */
    }

    p_opc[i++] = opc;

    UINT mod = (dsz==0 ? 0x00 : (dsz==1 ? 0x40 : 0x80));
    if (opc_sz==2) {
        /* ModR/M only */
        p_opc[i++] = mod | (UINT8)(reg_opc << 3) | (UINT8)base_gpr;
    } else {
        /* ModR/M + SIB */
        p_opc[i++] = mod | (UINT8)(reg_opc << 3) | 0x04;
        p_opc[i++] = 0x20 | (UINT8)base_gpr;
    }

    if (dsz==1) p_opc[i++] = (UINT8)displ;
    else
    if (dsz==4) {
        set_32uint_le(p_opc+i, displ);
        i+=4;
    }

finish:
    return i;
}

/* Support routine for opcode with [displ] translation */
static UINT trans_opc_mem_d(
    UINT8 opc, UINT32 displ, UINT reg_opc, UINT sp, UINT8 *p_opc, BOOL b_expnd)
{
    UINT i=0;

    if (sp<6 || sp>MAX_AIP_OPC) goto finish;

    sp-=6;  /* 6: 1 opc + 1 ModR/M + 4 displ */
    p_opc[i++] = opc;

    if (sp>0 && b_expnd) {
        /* displ in SIB (1 extra byte) */
        p_opc[i++] = 0x04 | (UINT8)(reg_opc << 3);
        p_opc[i++] = 0x25;
    } else {
        /* displ in Mod/RM*/
        p_opc[i++] = 0x05 | (UINT8)(reg_opc << 3);
    }

    set_32uint_le(p_opc+i, displ);
    i+=4;

finish:
    return i;
}

/* Translate ADD reg, imm: opcode (opc_add) */
UINT trans_add_imm(const emul_t *p_emul, UINT8 *p_opc)
{
    UINT32 sp = p_emul->ptch_sz-AIP_CALL_PT_SZ;
    return trans_grp1_opc(0x05, 0, p_emul->imm, p_emul->gpr, sp, p_opc, TRUE);
}

/* Translate MOV reg, reg: opcode (opc_mov_rr) */
UINT trans_mov_rr(const emul_t *p_emul, UINT8 *p_opc)
{
    UINT i=0;

    UINT32 sp = p_emul->ptch_sz-AIP_CALL_PT_SZ;
    if (sp<2 || sp>MAX_AIP_OPC) goto finish;

    /* alternative opcode: 0x89; 0xc0|gpr2<<3|gpr */
    p_opc[i++] = 0x8b;
    p_opc[i++] = 0xc0 | (UINT8)(p_emul->gpr << 3) | (UINT8)p_emul->gpr2;

finish:
    return i;
}

/* Translate MOV [mem], reg: opcode (opc_mov_mr) */
UINT trans_mov_mr(ULONG64 base_addr, const emul_t *p_emul, UINT8 *p_opc)
{
    UINT32 sp = p_emul->ptch_sz-AIP_CALL_PT_SZ;
    return trans_opc_mem_d(
        0x89, base_addr+p_emul->imm, (UINT)p_emul->gpr, sp, p_opc, TRUE);
}

/* Translate MOV [reg+displ], reg: opcode (opc_mov_rdr) */
UINT trans_mov_rdr(const emul_t *p_emul, UINT8 *p_opc)
{
    UINT32 sp = p_emul->ptch_sz-AIP_CALL_PT_SZ;
    return trans_opc_mem_rd(
        0x89, p_emul->gpr, p_emul->imm, (UINT)p_emul->gpr2, sp, p_opc, TRUE);
}

/* Get descriptive string of cmp argument (written under 'pc_out') */
void cmparg2str(ULONG64 base_addr,
    gpr_t gpr, UINT32 imm, BOOL is_mem, UINT ptr_sz, char *pc_out)
{
    char reg[8], immstr[16];

    if ((UINT)gpr > gpr_max) *reg=0;
    else strcpy(reg, GPR_NAMES[gpr]);

    if (imm && is_mem && ptr_sz==4) imm+=base_addr;

    if (imm || *reg==0) sprintf(immstr, "%s%08X", (*reg ? "+" : ""), imm);
    else *immstr=0;

    if (is_mem)
        sprintf(pc_out, "%s [%s%s]", (ptr_sz==1 ? "byte" : "dword"), reg, immstr);
    else
        sprintf(pc_out, "%s%s", reg, immstr);
}

/* Translate CMP opcode (opc_cmp_jcc, opc_cmp) */
UINT trans_cmp(
    ULONG64 base_addr, const emul_t *p_emul, UINT8 *p_opc, BOOL b_expnd)
{
    UINT i=0;
    args_tpy_t atpy = p_emul->atpy;
    UINT32 sp = p_emul->ptch_sz-AIP_CALL_PT_SZ;

    switch (atpy)
    {
    case a1_mem_b:
    case a1_mem_dw:
        {
            UINT8 opc;
            UINT reg_opc, isz=0;
            UINT32 imm = p_emul->imm2;

            UINT32 displ = p_emul->imm;
            if (displ && atpy==a1_mem_dw) displ+=base_addr;

            if ((UINT)p_emul->gpr2 > gpr_max)
            {
                /* cmp byte|dword [mem], imm */
                isz = (get_nonzero_sz(imm)<=1 ? 1 : 4);
                if ((sp<isz) || (atpy==a1_mem_b && isz==4)) goto finish;
                sp-=isz;

                opc = (atpy==a1_mem_b ? 0x80 : (isz==1 ? 0x83 : 0x81));
                reg_opc = 7;
            } else
            {
                /* cmp dword [mem], reg */
                if (imm || atpy==a1_mem_b) goto finish;

                opc = 0x39;
                reg_opc = (UINT)p_emul->gpr2;
            }

            i = ((UINT)p_emul->gpr > gpr_max ?
                trans_opc_mem_d(opc, displ, reg_opc, sp, p_opc, b_expnd):
                trans_opc_mem_rd(
                    opc, p_emul->gpr, displ, reg_opc, sp, p_opc, b_expnd));

            /* write immediate oper if necessary */
            if (i && isz)
            {
                sp-=i;

                if (b_expnd) {
                    if (sp>=3 && opc==0x83) { p_opc[0]=0x81; isz=4; sp-=3; }
                }

                if (isz==1) p_opc[i++] = (UINT8)imm;
                else
                if (isz==4) {
                    set_32uint_le(p_opc+i, imm);
                    i+=4;
                }
            }
        }
        break;

    case a2_mem_b: goto finish;
    case a2_mem_dw:
        {
            /* cmp reg, [mem] */
            if (p_emul->imm || ((UINT)p_emul->gpr > gpr_max)) goto finish;

            UINT8 opc = 0x3b;
            UINT32 displ = p_emul->imm2;
            if (displ) displ+=base_addr;

            i = ((UINT)p_emul->gpr2 > gpr_max ?
                trans_opc_mem_d(
                    opc, displ, (UINT)p_emul->gpr, sp, p_opc, b_expnd):
                trans_opc_mem_rd(opc, p_emul->gpr2,
                    displ, (UINT)p_emul->gpr, sp, p_opc, b_expnd));
        }
        break;

    case a12_nomem:
        if (((UINT)p_emul->gpr > gpr_max) || p_emul->imm) goto finish;

        if ((UINT)p_emul->gpr2 > gpr_max) {
            /* cmp reg, imm */
            i = trans_grp1_opc(
                0x3d, 7, p_emul->imm2, p_emul->gpr, sp, p_opc, b_expnd);
        } else {
            /* cmp reg, reg */
            if (sp<2 || sp>MAX_AIP_OPC || p_emul->imm2) goto finish;

            /* alternative opcode: 0x39; 0xc0|gpr2<<3|gpr */
            p_opc[i++] = 0x3b;
            p_opc[i++] = 0xc0 | (UINT8)(p_emul->gpr<<3) | (UINT8)p_emul->gpr2;
        }
        break;
    }

finish:
    return i;
}

/* Translate emulated code under 'p_emul' into opcode. In case of success (the
   func returns TRUE) 'pc_asm' will get opcode's description text, 'p_opc' is
   set into x86 machine code with its length written under 'p_opc_sz' and
   'p_opc_sp' will get whole space size devoted for emulated opcode machine code
   (it the space is greater than translated opcode size indicated by *p_opc_sz
   the extra bytes will be filled with NOPs). If 'p_opc_sz' is set to 0 then
   the func can not translate the emulated code into the machine code.
   Nevertheless the value under 'p_opc_sp' is set to space size devoted for
   emulated opcode but NOPs opcodes are not written.
 */
static BOOL emul2opc(ULONG64 base_addr, const emul_t *p_emul,
    char *pc_asm, UINT8 *p_opc, UINT *p_opc_sz, UINT *p_opc_sp)
{
    BOOL ret=FALSE;
    opc_t opc = p_emul->opc;

    *p_opc_sz=0;
    *p_opc_sp = p_emul->ptch_sz-AIP_CALL_PT_SZ;

    /* check validity of emul's data */
    if (opc==opc_add || opc==opc_mov_rr || opc==opc_mov_mr || opc==opc_mov_rdr)
    {
        if ((UINT)p_emul->gpr > gpr_max) {
            err_dbgprintf("GPR index outside boundary: 0x%02X\n", p_emul->gpr);
            goto finish;
        }
    }
    if (opc==opc_mov_rr || opc==opc_mov_rdr) {
        if ((UINT)p_emul->gpr2 > gpr_max) {
            err_dbgprintf("GPR2 index outside boundary: 0x%02X\n", p_emul->gpr2);
            goto finish;
        }
    }
    if (opc==opc_cmp_jcc) {
        if ((UINT)p_emul->jcc > jcc_max) {
            err_dbgprintf("Jcc index outside boundary: 0x%02X\n", p_emul->jcc);
            goto finish;
        }
    }

    switch (opc)
    {
    case opc_call:
        *p_opc_sz = trans_opc_displ(p_emul, p_emul->opc_addr, p_opc);
        sprintf(pc_asm, "%08X    call %08X",
            (UINT32)p_emul->opc_addr, (UINT32)p_emul->addr);
        break;

    case opc_jmp:
        *p_opc_sz = trans_opc_displ(p_emul, p_emul->opc_addr, p_opc);
        sprintf(pc_asm, "%08X    jmp %08X",
            (UINT32)p_emul->opc_addr, (UINT32)p_emul->addr);
        break;

    case opc_cmp_jcc:
        {
            emul_t emul = *p_emul;

            UINT cmp_sz = trans_cmp(base_addr, &emul, p_opc, FALSE);
            if (cmp_sz > 0) {
                emul.ptch_sz-=cmp_sz;
                UINT jcc_sz = trans_opc_displ(
                    &emul, p_emul->opc_addr+cmp_sz, p_opc+cmp_sz);
                if (jcc_sz>0) *p_opc_sz = cmp_sz+jcc_sz;
            }

            char a1[36], a2[36];
            UINT a1_ptr_sz = (p_emul->atpy==a1_mem_dw ? 4 :
                (p_emul->atpy==a1_mem_b ? 1 : 0));
            UINT a2_ptr_sz = (p_emul->atpy==a2_mem_dw ? 4 :
                (p_emul->atpy==a2_mem_b ? 1 : 0));

            cmparg2str(base_addr,
                p_emul->gpr, p_emul->imm, a1_ptr_sz!=0, a1_ptr_sz, a1);
            cmparg2str(base_addr,
                p_emul->gpr2, p_emul->imm2, a2_ptr_sz!=0, a2_ptr_sz, a2);
            sprintf(pc_asm, "%08X    cmp %s, %s; %08X    %s %08X",
                (UINT32)p_emul->opc_addr, a1, a2,
                (UINT32)(p_emul->opc_addr+cmp_sz), JCC_NAMES[p_emul->jcc],
                (UINT32)p_emul->addr);
        }
        break;

    case opc_cmp:
        {
            *p_opc_sz = trans_cmp(base_addr, p_emul, p_opc, TRUE);

            char a1[36], a2[36];
            UINT a1_ptr_sz = (p_emul->atpy==a1_mem_dw ? 4 :
                (p_emul->atpy==a1_mem_b ? 1 : 0));
            UINT a2_ptr_sz = (p_emul->atpy==a2_mem_dw ? 4 :
                (p_emul->atpy==a2_mem_b ? 1 : 0));

            cmparg2str(base_addr,
                p_emul->gpr, p_emul->imm, a1_ptr_sz!=0, a1_ptr_sz, a1);
            cmparg2str(base_addr,
                p_emul->gpr2, p_emul->imm2, a2_ptr_sz!=0, a2_ptr_sz, a2);
            sprintf(pc_asm, "%08X    cmp %s, %s",
                (UINT32)p_emul->opc_addr, a1, a2);
        }
        break;

    case opc_add:
        *p_opc_sz = trans_add_imm(p_emul, p_opc);
        sprintf(pc_asm, "%08X    add %s, %08X",
            (UINT32)p_emul->opc_addr, GPR_NAMES[p_emul->gpr], p_emul->imm);
        break;

    case opc_mov_rr:
        *p_opc_sz = trans_mov_rr(p_emul, p_opc);
        sprintf(pc_asm, "%08X    mov %s, %s",
            (UINT32)p_emul->opc_addr, GPR_NAMES[p_emul->gpr],
            GPR_NAMES[p_emul->gpr2]);
        break;

    case opc_mov_mr:
        *p_opc_sz = trans_mov_mr(base_addr, p_emul, p_opc);
        sprintf(pc_asm, "%08X    mov [%08X], %s",
            (UINT32)p_emul->opc_addr, (UINT32)(base_addr+p_emul->imm),
            GPR_NAMES[p_emul->gpr]);
        break;

    case opc_mov_rdr:
        *p_opc_sz = trans_mov_rdr(p_emul, p_opc);
        sprintf(pc_asm, "%08X    mov [%s+%08X], %s",
            (UINT32)p_emul->opc_addr, GPR_NAMES[p_emul->gpr], p_emul->imm,
            GPR_NAMES[p_emul->gpr2]);
        break;

    default:
        err_dbgprintf("Unknown emulated opcode: 0x%02X\n", opc);
        goto finish;
    }

    if (*p_opc_sz>0) {
        /* fill remaining bytes of opcode space with NOPs */
        for (UINT i=*p_opc_sz; i<*p_opc_sp; i++) p_opc[i] = 0x90;
    }

    ret=TRUE;

finish:
    return ret;
}

/* Free import list retrieved by get_imports() */
void free_imports(mod_imp_t *p_mods)
{
    void *to_free;

    for (mod_imp_t *p_mod=p_mods; p_mod;) {
        for (proc_imp_t *p_proc=p_mod->p_proc; p_proc; ) {
            to_free=p_proc;
            p_proc=p_proc->next;
            free(to_free);
        }
        to_free=p_mod;
        p_mod=p_mod->next;
        free(to_free);
    }
}

/* Retrieve imports and write a pointer to the imports list under 'pp_libs'.
   Number of imported libs is written under 'p_nlib'. 'in_addr' points to aip
   env or ASPR imports internal struct depending on 'b_aip_env_addr' flag.
   Returns TRUE on success. The caller shall free the retrieved list by calling
   free_imports().
 */
BOOL get_imports(aspr_ver_t ver, ULONG64 in_addr, BOOL b_aip_env_addr,
    mod_imp_t **pp_libs, UINT *p_nlib)
{
    BOOL ret=FALSE;

    *pp_libs = NULL;
    *p_nlib = 0;
    mod_imp_t *p_prev_lib=NULL;

    ULONG64 imports_addr=in_addr;
    if (b_aip_env_addr) {
        aip_env_t env;
        if (!get_aip_env(ver, in_addr, &env)) goto finish;
        else imports_addr=env.imports_addr;
    }

    imports_t imps;
    size_t ids_fld_len;
    if (!get_imps(ver, imports_addr, &imps, &ids_fld_len, b_aip_env_addr))
        goto finish;

    /* libs iter */
    for (ULONG64 addr = imps.imp_dsc_addr+ids_fld_len, next_addr;;
        (*p_nlib)++, addr=next_addr)
    {
        ULONG cb;
        UINT8 lib_hdr[10];  /* last(4) + end_off(4) + lib_id(2) */

        if (!(read_memory(addr, lib_hdr, sizeof(lib_hdr), &cb) &&
            cb==sizeof(lib_hdr))) goto finish;
        addr+=cb;

        UINT32 last = get_32uint_le(&lib_hdr[0]);
        UINT32 end_off = get_32uint_le(&lib_hdr[4]);
        UINT16 lib_id = get_16uint_le(&lib_hdr[8]);

        /* check if last module has been reached */
        if (!last) break;

        /* next entry addr; end_off is relative to the end_off field addr */
        next_addr = addr+end_off-(sizeof(end_off)+sizeof(lib_id));

        char lib_name[MAX_PATH+1];
        if (!string_cpy_lt(lib_name, addr, sizeof(lib_name))) goto finish;

        size_t lib_name_len = strlen(lib_name);
        addr += lib_name_len+1;

        /* create new list entry */
        mod_imp_t *p_lib;
        size_t to_alloc = sizeof(*p_lib)+
            (lib_name_len>0 ? lib_name_len+1 : sizeof(CAPI_DLL));
        p_lib = (mod_imp_t*)malloc(to_alloc);
        if (!p_lib) goto finish;

        p_lib->mod_base = 0;
        p_lib->iat_addr = last+imps.mod_base;
        p_lib->pc_mod_name = (char*)(p_lib+1);
        strcpy(p_lib->pc_mod_name, lib_name);
        p_lib->mod_id = lib_id;
        p_lib->n_procs = 0;
        p_lib->p_proc = NULL;
        p_lib->next = NULL;

        /* link element to the libs list */
        if (!*pp_libs) *pp_libs=p_lib;
        if (p_prev_lib) p_prev_lib->next=p_lib;
        p_prev_lib=p_lib;

        /* resolve module base and find its export dir */
        size_t modn_len;
        char *pc_modn = get_mod_name(lib_name, &modn_len);
        pc_modn[modn_len]=0;

        mod_exp_dir_t expdir;
        ULONG64 mod_base;
        if (reslv_mod(pc_modn, &expdir, FALSE)) p_lib->mod_base=expdir.mod_base;

        /* procs iter */
        for (proc_imp_t *p_prev_proc=NULL;;)
        {
            UINT8 proc_hdr[3];  /* imp_tpy(1) + proc_id(2) */

            if (!(read_memory(addr, proc_hdr, sizeof(proc_hdr), &cb) &&
                cb==sizeof(proc_hdr))) goto finish;
            addr+=cb;

            UINT8 imp_tpy = proc_hdr[0];
            UINT16 proc_id = get_16uint_le(&proc_hdr[1]);

            /* translate the type */
            imp_tpy_t proc_tpy=imp_key2_noiat;

            if (imp_tpy==imps.imp_key1_noiat) proc_tpy=imp_key1_noiat;
            else
            if (imp_tpy==imps.imp_key1_iat) proc_tpy=imp_key1_iat;
            else
            if (imp_tpy==imps.imp_plain) proc_tpy=imp_plain;
            else
            if (imp_tpy==imps.imp_stl_re) proc_tpy=imp_stl_re;
            else
            if (imp_tpy==imps.imp_stl_gpa) proc_tpy=imp_stl_gpa;
            else
            if (imp_tpy==imps.imp_stl_gpa2) proc_tpy=imp_stl_gpa2;
            else
            if (imp_tpy==imps.imp_key2_iat) proc_tpy=imp_key2_iat;
            else
            if (imp_tpy==imps.imp_key2_noiat) proc_tpy=imp_key2_noiat;

            UINT32 proc_ord = (UINT32)-1;
            char proc_name[MAX_SYM_NAME+1];
            proc_name[0] = 0;

            /* check if last import has been reached */
            if (imp_tpy==imps.imp_endmrk) break;
            else
            if (proc_tpy==imp_plain)
            {
                UINT32 dw;
                if (!(read_memory(addr, &dw, sizeof(dw), &cb) &&
                    cb==sizeof(dw))) goto finish;
                addr+=cb;

                ULONG64 proc_name_addr = DEBUG_EXTEND64(get_32uint_le(&dw));

                if (!(proc_name_addr & ~0xffff)) {
                    proc_ord = (UINT32)proc_name_addr;
                    sprintf(proc_name, "ordinal #0x%04", proc_ord);
                } else {
                    if (!string_cpy_lt(proc_name, proc_name_addr, MAX_SYM_NAME+1))
                        goto finish;
                    addr+=strlen(proc_name)+1;
                }
            } else
            {
                if (ver==aspr_unknown && proc_tpy==imp_stl_gpa2)
                {
                    UINT8 b;
                    if (!(read_memory(addr, &b, sizeof(b), &cb) &&
                        cb==sizeof(b))) goto finish;
                    addr+=cb;

                    sprintf(&proc_name[0], "capi_%02X", (UINT)b);

                    if (!lib_name_len) {
                        lib_name_len = sizeof(CAPI_DLL)-1;
                        strcpy(p_lib->pc_mod_name, CAPI_DLL);
                    }
                } else
                {
                    UINT16 w;

                    /* read next 2 bytes long word */
                    if (!(read_memory(addr, &w, sizeof(w), &cb) &&
                        cb==sizeof(w))) goto finish;
                    addr+=cb;

                    if ((proc_tpy!=imp_stl_re && proc_tpy!=imp_stl_gpa) ||
                        (ver==aspr_unknown && proc_tpy==imp_stl_gpa))
                    {
                        /* key/key2 types */
                        UINT procn_len = get_16uint_le(&w);

                        if (procn_len > sizeof(proc_name)-1) {
                            err_dbgprintf("Imported proc name too long (%d), "
                                "proc_id: 0x%04X, lib_id: 0x%04X\n",
                                procn_len, (UINT)proc_id, (UINT)lib_id);
                            goto finish;
                        } else
                        if (!procn_len) {
                            err_dbgprintf("No proc name: proc_id: 0x%04X, lib_id: "
                                "0x%04X\n", (UINT)proc_id, (UINT)lib_id);
                            goto finish;
                        }

                        if (!(read_memory(addr, &proc_name, procn_len, &cb) &&
                            cb==procn_len)) goto finish;

                        BOOL key1 = (proc_tpy==imp_key1_noiat ||
                                    proc_tpy==imp_key1_iat ||
                                    proc_tpy==imp_stl_gpa2 ||
                                    (ver==aspr_unknown && proc_tpy==imp_stl_gpa) ?
                                        TRUE : FALSE);

                        decode((UINT8*)&proc_name[0], procn_len,
                            (key1 ? imps.key1 : imps.key2),
                            (key1 ? sizeof(imps.key1) : sizeof(imps.key2)));

                        /* skip proc name */
                        addr+=procn_len;
                    } else
                    {
                        switch (proc_tpy)
                        {
                        case imp_stl_re:
                            sprintf(&proc_name[0], "RaiseException");
                            break;

                        case imp_stl_gpa:
                            strcpy(&proc_name[0], "GetProcAddress");
                            break;
                        };
                    }
                }
            }

            /* create new list entry */
            proc_imp_t *p_proc;
            to_alloc = sizeof(*p_proc)+strlen(proc_name)+1;
            p_proc = (proc_imp_t*)malloc(to_alloc);
            if (!p_proc) goto finish;

            p_proc->proc_addr=0;
            p_proc->pc_proc_name = (char*)(p_proc+1);
            strcpy(p_proc->pc_proc_name, proc_name);
            p_proc->proc_ord = proc_ord;
            p_proc->tpy = proc_tpy;
            p_proc->proc_id = proc_id;
            p_proc->next = NULL;

            /* resolve proc addr */
            reslv_import(&expdir,
                p_proc->pc_proc_name, proc_ord, &p_proc->proc_addr, FALSE);

            /* link element to the procs list */
            if (!p_prev_proc) p_prev_lib->p_proc=p_proc;
            else p_prev_proc->next=p_proc;
            p_prev_proc=p_proc;

            p_prev_lib->n_procs++;
        }
    }

    ret=TRUE;
finish:
    if (!ret && *pp_libs) { free_imports(*pp_libs); *pp_libs=NULL; *p_nlib=0; }
    return ret;
}

/* Free patches list retrieved by get_patches() */
void free_patches(imp_patch_t *p_ptchs)
{
    void *to_free;

    for (imp_patch_t *p_patch=p_ptchs; p_patch;) {
        to_free=p_patch;
        p_patch=p_patch->next;
        free(to_free);
    }
}

/* Retrieve patches and write pointer to the patches list under 'pp_ptchs'.
   Number of elements in the list is written under 'p_nptch'. Returns TRUE on
   success. The caller shall free the retrieved list by calling free_patches().
 */
BOOL get_patches(aspr_ver_t ver, ULONG64 aip_env_addr, ULONG64 chk_mem_addr,
    DWORD flags, imp_patch_t **pp_ptchs, UINT *p_nptch)
{
    /* import patch's details */
    typedef struct _ptch_imp_t
    {
        mod_imp_t *p_lib;
        proc_imp_t *p_proc;
        ULONG64 iat_elem_addr;
    } ptch_imp_t;


    BOOL ret=FALSE;

    UINT nlib;
    mod_imp_t *p_libs=NULL;
    BOOL ld_libs=FALSE;

    ptch_t *ptchs=NULL;
    emul_t *emuls=NULL;


    *pp_ptchs = NULL;
    *p_nptch = 0;

    aip_env_t env;
    if (!get_aip_env(ver, aip_env_addr, &env)) goto finish;

    aspr_ver_t imps_ver;
    get_loaded_imports(&imps_ver, &p_libs, &nlib);
    if (p_libs==NULL || nlib==0) {
        /* get imports from env if not loaded */
        warn_dbgprintf(
            "No loaded imports; retrieving them from the ASPR env struct. "
            "The IAT addresses are destroyed, imports patches must be done "
            "manually.\n");
        if (!get_imports(ver, aip_env_addr, TRUE, &p_libs, &nlib)) {
            err_dbgprintf("Can't retrieve list of imports\n");
            goto finish;
        }
    } else {
        if (ver!=imps_ver) {
            warn_dbgprintf("Versions mismatch between loaded imports version "
                "and the currently set one\n");
        }
        ld_libs=TRUE;
    }

    if (!get_ptchs_dt(&env, chk_mem_addr, &ptchs)) {
        err_dbgprintf("Can't retrieve list of patches\n");
        goto finish;
    }
    if (!get_emuls_dt(&env, &emuls)) {
        err_dbgprintf("Can't retrieve list of emulated opcodes\n");
        goto finish;
    }

    imp_patch_t *p_prev_patch=NULL;
    for (UINT32 i=0; i<env.n_ptchs; i++, (*p_nptch)++)
    {
        /* look for matching import
         */
        UINT dups=0;
        ptch_imp_t ptch_imp = {};

        const UINT MAX_DUPS=50;
        ptch_imp_t dup_imps[MAX_DUPS];

        for (mod_imp_t *p_lib=p_libs; p_lib; p_lib=p_lib->next)
        {
            if (ptchs[i].lib_id==p_lib->mod_id)
            {
                int proc_i;
                proc_imp_t *p_proc;
                for (proc_i=0, p_proc=p_lib->p_proc; p_proc;
                    p_proc=p_proc->next, proc_i++)
                {
                    if (ptchs[i].proc_id==p_proc->proc_id)
                    {
                        UINT64 iat_elem_addr = p_lib->iat_addr +
                            proc_i*sizeof(IMAGE_THUNK_DATA32);

                        if (dups<MAX_DUPS) {
                            dup_imps[dups].p_lib = p_lib;
                            dup_imps[dups].p_proc = p_proc;
                            dup_imps[dups].iat_elem_addr = iat_elem_addr;
                        }

                        dups++;
                        if (dups>1) {
                            if (dups>2) {
                                dbgprintf(" 0x%p", iat_elem_addr);
                            }  else {
                                info_dbgprintf(
                                    "Import patch at 0x%p references dupl. "
                                    "import %s!%s; IAT addrs: 0x%p 0x%p",
                                    ptchs[i].ptch_addr, p_lib->pc_mod_name,
                                    p_proc->pc_proc_name, dup_imps[0].iat_elem_addr,
                                    dup_imps[1].iat_elem_addr);
                            }
                        }
                    }
                }
            }
        }

        if (!dups) {
            err_dbgprintf("Can't find patched import: lib id: 0x%04X, proc "
                "id: 0x%04X\n", ptchs[i].lib_id, ptchs[i].proc_id);
            goto finish;
        } else
        {
            if (flags&LDPTCHS_1_DUPL || dups==1) {
                ptch_imp = dup_imps[0];
            } else {
                /* set consecutive patches to the consecutive
                   dups (better accuracy for the Delphi apps ) */
                UINT dup_i=0;
                for (UINT32 j=0; j<=i; j++) {
                    if (ptchs[j].lib_id==ptchs[i].lib_id &&
                        ptchs[j].proc_id==ptchs[i].proc_id)
                    {
                        ptch_imp = dup_imps[dup_i];
                        if ((dup_i+1)<min(MAX_DUPS, dups)) dup_i++;
                        else break;
                    }
                }
            }

            if (dups>1) dbgprintf("; set to 0x%p\n", ptch_imp.iat_elem_addr);
        }

        /* get emulated opcode (if present) */
        emul_t *p_emul=NULL;
        UINT8 eopc[MAX_EMUL_PATCH];
        UINT eopc_sz=0, eopc_sp=0;
        char eopc_asm[120];
        *eopc_asm = 0;

        if ((ptchs[i].ptch_tpy==ptch_aip) && (ptchs[i].emul_id < env.n_emuls))
        {
            p_emul = &emuls[ptchs[i].emul_id];
            /* set opcode addr as next to the AIP call */
            p_emul->opc_addr = ptchs[i].ptch_addr+AIP_CALL_PT_SZ;

            if (!emul2opc(env.mod_base, p_emul, eopc_asm,
                eopc, &eopc_sz, &eopc_sp))
            {
                err_dbgprintf("Can't retrieve emulated opcode for AIP patch at "
                    "0x%p\n", ptchs[i].ptch_addr);
                goto finish;
            }
        }

        /* create & fill a new patch element
         */
        char *pc_libdsc_frmt="%s!%s [0x%p]";
        size_t libdsc_len = strlen(pc_libdsc_frmt)+
            strlen(ptch_imp.p_lib->pc_mod_name)+
            strlen(ptch_imp.p_proc->pc_proc_name)+20;

        imp_patch_t *p_patch;
        size_t to_alloc = sizeof(*p_patch)+libdsc_len+
            (p_emul ? sizeof(*(p_patch->p_emul))+strlen(eopc_asm)+1 : 0);

        UINT8 *p_mem = (UINT8*)malloc(to_alloc);
        if (!p_mem) goto finish;

        p_patch = (imp_patch_t*)p_mem;

        p_patch->pc_desc = (char*)(p_patch+1);
        sprintf(p_patch->pc_desc, pc_libdsc_frmt, ptch_imp.p_lib->pc_mod_name,
            ptch_imp.p_proc->pc_proc_name, ptch_imp.p_proc->proc_addr);
        p_patch->addr = ptchs[i].ptch_addr;

        p_patch->sp_len = p_patch->len = AIP_CALL_PT_SZ;

        p_patch->type = ptchs[i].ptch_tpy;
        p_patch->ref_jmp = (ptchs[i].ref_tpy==opc_jmp ? TRUE : FALSE);

        p_patch->proc_tpy = ptch_imp.p_proc->tpy;
        p_patch->proc_addr = ptch_imp.p_proc->proc_addr;

        p_patch->patch[0] = 0xff;
        /* jmp/call dword [iat_elem] */
        p_patch->patch[1] = (p_patch->ref_jmp ? 0x25 : 0x15);

        /* imported proc's IAT element address */
        p_patch->iat_elem_addr = ptch_imp.iat_elem_addr;

        ULONG cb;
        IMAGE_THUNK_DATA32 iat_elem;
        if (read_memory(p_patch->iat_elem_addr, &iat_elem,
            sizeof(iat_elem), &cb) && cb==sizeof(iat_elem))
        {
            /* encode IAT addr for the jmp/call opcode */
            p_patch->patch[2] = p_patch->iat_elem_addr         & 0xff;
            p_patch->patch[3] = (p_patch->iat_elem_addr >> 8)  & 0xff;
            p_patch->patch[4] = (p_patch->iat_elem_addr >> 16) & 0xff;
            p_patch->patch[5] = (p_patch->iat_elem_addr >> 24) & 0xff;
        } else {
            /* IAT elem may not be accessible since it has been
               already destroyed by ASPR; patching is not possible */
            p_patch->len=0;
        }

        p_patch->p_emul = NULL;
        p_patch->next = NULL;

        /* create & fill a new emulated patch element (if exists) */
        if (p_emul)
        {
            p_patch->p_emul = (emul_patch_t*)(p_patch->pc_desc+libdsc_len);

            p_patch->p_emul->pc_desc = (char*)(p_patch->p_emul+1);
            strcpy(p_patch->p_emul->pc_desc, eopc_asm);

            p_patch->p_emul->addr = p_emul->opc_addr;

            p_patch->p_emul->sp_len = eopc_sp;

            if (eopc_sz>0) {
                p_patch->p_emul->len = eopc_sp;
                memcpy(p_patch->p_emul->patch, eopc, sizeof(eopc));
            } else {
                p_patch->p_emul->len = 0;
            }
        }

        /* link element to the patches list */
        if (!*pp_ptchs) *pp_ptchs=p_patch;
        if (p_prev_patch) p_prev_patch->next=p_patch;
        p_prev_patch=p_patch;
    }

    ret=TRUE;
finish:
    if (emuls) free(emuls);
    if (ptchs) free(ptchs);
    if (!ld_libs && p_libs) free_imports(p_libs);

    if (!ret && *pp_ptchs) {
        free_patches(*pp_ptchs);
        *pp_ptchs=NULL;
        *p_nptch=0;
    }

    return ret;
}

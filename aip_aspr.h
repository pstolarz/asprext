/*
   Copyright (c) 2016 Piotr Stolarz
   asprext: ASProtect reverse engineering & analysis WinDbg extension

   Distributed under the GNU General Public License (the License)
   see accompanying file LICENSE for details.

   This software is distributed WITHOUT ANY WARRANTY; without even the
   implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
   See the License for more information.
 */

#ifndef __ASPREXT_AIP_ASPR_H__
#define __ASPREXT_AIP_ASPR_H__

#include "config.h"
#include "imports.h"

BOOL call_dt_hndl(ULONG64 call_addr, ULONG64 dt_addr, UINT32 *p_ret);

void free_imports(mod_imp_t *p_mods);

BOOL get_imports(aspr_ver_t ver, ULONG64 in_addr,
    BOOL b_aip_env_addr, mod_imp_t **pp_libs, UINT *p_nlib);

void free_patches(imp_patch_t *p_ptchs);

BOOL get_patches(aspr_ver_t ver, ULONG64 aip_env_addr, ULONG64 chk_mem_addr,
    DWORD flags, imp_patch_t **pp_ptchs, UINT *p_nptch);


extern const char *GPR_NAMES[];
extern const char *JCC_NAMES[];

/* emulated opcodes ids */
typedef enum _opc_t
{
    opc_call=0,         /* CALL addr (AIP/poly) */
    opc_jmp,            /* JMP addr (AIP/poly) */
    opc_jcc,            /* Jcc (poly) */
    opc_cmp_jcc,        /* CMP; Jcc addr (AIP/poly) */
    opc_cmp,            /* CMP (AIP) */
    opc_add,            /* ADD reg, imm (AIP) */
    opc_mov_rr,         /* MOV reg, reg (AIP) */
    opc_mov_mr,         /* MOV [mem], reg (AIP) */
    opc_mov_rdr         /* MOV [reg+displ], reg (AIP) */
} opc_t;

/* jcc codes */
typedef enum _jcc_t
{
    jo=0, jno,
    jb, jae,
    je, jne,
    jp, jnp,
    js, jns,
    jbe, ja,
    jl, jge,
    jle, jg,

    jcc_max=jg
} jcc_t;

/* gpr ids */
typedef enum _gpr_t
{
    eax=0,
    ecx,
    edx,
    ebx,
    esp,
    ebp,
    esi,
    edi,

    gpr_max=edi
} gpr_t;

typedef enum _args_tpy_t
{
    a1_mem_dw=0,
    a2_mem_dw,
    a1_mem_b,
    a2_mem_b,
    a12_nomem           /* arg1/2 both regs or reg/imm */
} args_tpy_t;

/* emulated opcode data */
typedef struct _emul_t
{
    opc_t opc;          /* opcode id */
    ULONG64 opc_addr;   /* opcode addr */
    UINT32 ptch_sz;     /* AIP only: whole patch size: AIP call + emul opcode */
    ULONG64 addr;       /* address oper */
    ULONG64 addr2;      /* poly only: additional address oper */
    jcc_t jcc;          /* Jcc code */
    gpr_t gpr;          /* 1st oper */
    gpr_t gpr2;         /* 2nd oper */
    UINT32 imm;         /* imm oper */
    UINT32 imm2;        /* 2nd imm oper */
    args_tpy_t atpy;    /* ModR/M args types */
} emul_t;


UINT trans_opc_displ(const emul_t *p_emul, UINT32 opc_addr, UINT8 *p_opc);
UINT trans_add_imm(const emul_t *p_emul, UINT8 *p_opc);
UINT trans_mov_rr(const emul_t *p_emul, UINT8 *p_opc);
UINT trans_mov_mr(ULONG64 base_addr, const emul_t *p_emul, UINT8 *p_opc);
UINT trans_mov_rdr(const emul_t *p_emul, UINT8 *p_opc);
UINT trans_cmp(
    ULONG64 base_addr, const emul_t *p_emul, UINT8 *p_opc, BOOL b_expnd);

void cmparg2str(ULONG64 base_addr,
    gpr_t gpr, UINT32 imm, BOOL is_mem, UINT ptr_sz, char *pc_out);

#endif /* __ASPREXT_AIP_ASPR_H__ */

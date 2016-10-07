/*
   Copyright (c) 2016 Piotr Stolarz
   asprext: ASProtect reverse engineering & analysis WinDbg extension

   Distributed under the GNU General Public License (the License)
   see accompanying file LICENSE for details.

   This software is distributed WITHOUT ANY WARRANTY; without even the
   implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
   See the License for more information.
 */

#ifndef __ASPREXT_IMORTS_H__
#define __ASPREXT_IMORTS_H__

#include "config.h"

typedef enum _imp_tpy_t
{
    imp_key1_noiat,
    imp_key1_iat,
    imp_plain,
    imp_stl_re,
    imp_stl_gpa,
    imp_stl_gpa2,
    imp_key2_iat,
    imp_key2_noiat
} imp_tpy_t;

typedef struct _proc_imp_t
{
    ULONG64 proc_addr;      /* resolved addr of the proc; NULL if can't
                               be resolved */
    char *pc_proc_name;     /* imported proc name */
    UINT32 proc_ord;        /* ordinal num (valid if != -1) */

    imp_tpy_t tpy;          /* type of import */
    UINT32 proc_id;         /* aspr proc id */

    _proc_imp_t *next;      /* next proc in the chain */
} proc_imp_t;

typedef struct _mod_imp_t
{
    ULONG64 mod_base;       /* module base; NULL if can't be resolved */
    ULONG64 iat_addr;       /* start of the module's IAT table; value may be
                               unreliable if mod's IAT addr was destroyed */
    char *pc_mod_name;      /* module name */
    UINT32 mod_id;          /* aspr mod id */

    UINT n_procs;           /* number of imports for this module */
    proc_imp_t *p_proc;     /* 1st imported proc */

    _mod_imp_t *next;      /* next module in the chain */
} mod_imp_t;


/* maximum allowed space for an AIP emulated opcode */
#define MAX_AIP_OPC         25U

/* max patches lengths */
#define MAX_IMP_PATCH       16U
#define MAX_EMUL_PATCH      (2*MAX_AIP_OPC)


typedef enum _ptch_tpy_t
{
    ptch_sip,
    ptch_aip,
    ptch_esip           /* enhanced SIP */
} ptch_tpy_t;

typedef struct _emul_patch_t
{
    char *pc_desc;          /* description */

    ULONG64 addr;           /* address of apply */
    UINT sp_len;            /* length of patch space >= patch length */
    UINT len;               /* patch length */
    UINT8 patch[MAX_EMUL_PATCH];    /* patch bytes */
} emul_patch_t;

typedef struct _imp_patch_t
{
    char *pc_desc;          /* description */

    ULONG64 addr;           /* address of apply */
    UINT sp_len;            /* length of patch space >= patch length */
    UINT len;               /* patch length; if 0 patch is not applicable since
                               the import's IAT entry is not accessible */
    UINT8 patch[MAX_IMP_PATCH];         /* patch bytes */

    ptch_tpy_t type;        /* patch type */
    BOOL ref_jmp;           /* FALSE: CALL reference, TRUE: JMP reference */

    /* some info related referenced import
       proc used for patching proc's IAT entry */
    imp_tpy_t proc_tpy;     /* type of import */
    ULONG64 proc_addr;      /* resolved addr of the proc; NULL if can't
                               be resolved */
    ULONG64 iat_elem_addr;  /* address of proc's IAT element; value may be
                               unreliable if mod's IAT addr was destroyed */

    emul_patch_t *p_emul;   /* if !=NULL then the patch is associated with
                               some emulated opcode */
    _imp_patch_t *next;
} imp_patch_t;


#define LDIMPS_AIP_ENV_ADDR 0x01U

#define LDPTCHS_1_DUPL      0x01U

#define APLPTCHS_IAT_PATCH  0x01U
#define APLPTCHS_VERBOSE    0x02U


void get_loaded_imports(aspr_ver_t *p_ver, mod_imp_t **pp_mods, UINT *p_nmods);
void load_imports(ULONG64 in_addr, DWORD flags);
void unload_imports();
void print_imports();
void print_imp_spec();

void load_patches(ULONG64 aip_env_addr, ULONG64 chk_mem_addr, DWORD flags);
void unload_patches();
void apply_patches(DWORD flags);
void print_patches();


/* export directory's fields */
typedef struct _mod_exp_dir_t
{
    ULONG64 mod_base;       /* module's base addr */

    /* exp dir data */
    DWORD ord_base;         /* ordinal's base */
    DWORD n_faddrs;         /* number of functions in EAT */
    DWORD n_fnames;         /* number of exported names */
    ULONG64 mod_name_addr;  /* module's name address */
    ULONG64 faddrs_addr;    /* address of EAT */
    ULONG64 fnames_addr;    /* address of names table */
    ULONG64 fords_addr;     /* address of ordinals table */
} mod_exp_dir_t;


BOOL reslv_mod(const char *pc_mod_name, mod_exp_dir_t *p_ed, BOOL b_logs);

BOOL reslv_import(const mod_exp_dir_t *p_ed,
    const char *pc_proc_name, UINT32 proc_ord, ULONG64 *p_proc_addr, BOOL b_logs);

#endif /* __ASPREXT_IMORTS_H__ */

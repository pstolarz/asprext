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
#include "init_aspr.h"
#include "aip_aspr.h"


#define DESTR_START_OFF     0x0000U
#define CONSTR_START_OFF    0x0008U
#define BASE_INIT_CODE_OFF  0x0021U

/*
    0000  50                push eax                ; destr. start
    0001  6A04              push byte +0x4
    0003  EB06              jmp short 0xb
    0005  90                nop
    0006  90                nop
    0007  90                nop
    0008  50                push eax                ; constr. start
    0009  6A00              push byte +0x0
    000B  E800000000        call dword 0x10
    0010  58                pop eax
    0011  83C020            add eax,byte +0x20
    0014  010424            add [esp],eax
    0017  8B0424            mov eax,[esp]
    001A  8B00              mov eax,[eax]
    001C  85C0              test eax,eax
    001E  740D              jz 0x2d
    0020  0500000000        add eax,0x0             ; base of the init code
                                                    ; at the offset 0x0021
    0025  FFD0              call eax
    0027  83042408          add dword [esp],byte +0x8
    002B  EBEA              jmp short 0x17
    002D  58                pop eax
    002E  58                pop eax
    002F  C3                ret
*/
static UINT8 init_code[] =
{
    0x50,0x6a,0x04,0xeb,0x06,0x90,0x90,0x90,0x50,0x6a,0x00,0xe8,0x00,0x00,0x00,
    0x00,0x58,0x83,0xc0,0x20,0x01,0x04,0x24,0x8b,0x04,0x24,0x8b,0x00,0x85,0xc0,
    0x74,0x0d,0x05,0x00,0x00,0x00,0x00,0xff,0xd0,0x83,0x04,0x24,0x08,0xeb,0xea,
    0x58,0x58,0xc3
};

/* default out tab of get_init_hndls() */
static UINT32 def_out_tab[0x100] = {0};

/* free init handlers returned by get_init_hndls() */
static void free_init_hndls(UINT32 *p_init_hndls) {
    if (p_init_hndls && p_init_hndls!=def_out_tab) free(p_init_hndls);
}

/* Call init handlers of the constructor/destructor handler whose proc addr is
   'hndl_addr'. the func fills 'pp_out' and 'p_out_len' with result table and
   its length containing the handlers addresses. The table shall be freed by
   free_init_hndls().
 */
static BOOL get_init_hndls(ULONG64 hndl_addr, UINT32 **pp_out, size_t *p_out_len)
{
    /* base id for internal breakpoints */
    const UINT BP_ID_BASE = 1000;

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

    size_t tab_len=ARRAY_SZ(def_out_tab);
    *pp_out = def_out_tab;
    *p_out_len=0;

    BOOL rest_need=FALSE, bps_clear=FALSE, ret=FALSE;

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

    DEBUG_VALUE eip_r, esp_r;
    /* eip on the called proc */
    eip_r.I32 = (UINT32)hndl_addr;
    eip_r.Type = DEBUG_VALUE_INT32;

    if (DebugRegisters->SetValue(reg_ids[eip], &eip_r)!=S_OK) goto finish;
    rest_need=TRUE;

    /* step into the poly-handler */
    if (DebugControl->Execute(
            DEBUG_OUTCTL_IGNORE, "pc; t", DEBUG_EXECUTE_NOT_LOGGED)!=S_OK ||
        DebugControl->WaitForEvent(0, INFINITE)!=S_OK) goto finish;

    ULONG cb;
    char cmd[32];
    UINT8 rd_buf[4];

    /* set exit bp */
    if (DebugRegisters->GetValue(reg_ids[esp], &esp_r)!=S_OK ||
        !(read_memory(DEBUG_EXTEND64(esp_r.I32), rd_buf, 4, &cb) && cb==4))
        goto finish;

    sprintf(cmd, "ba[0n%d] e1 0x%08X", BP_ID_BASE, get_32uint_le(rd_buf));
    if (DebugControl->Execute(
        DEBUG_OUTCTL_IGNORE, cmd, DEBUG_EXECUTE_NOT_LOGGED)!=S_OK) goto finish;
    bps_clear=TRUE;

    for (BOOL hndl_bp_set=FALSE;;)
    {
        if (DebugControl->Execute(DEBUG_OUTCTL_IGNORE,
                (hndl_bp_set ? "g" : "pct"), DEBUG_EXECUTE_NOT_LOGGED)!=S_OK ||
            DebugControl->WaitForEvent(0, INFINITE)!=S_OK) goto finish;

        /* get an opcode at the break */
        if (DebugRegisters->GetValue(reg_ids[eip], &eip_r)!=S_OK ||
            !(read_memory(DEBUG_EXTEND64(eip_r.I32), rd_buf, 2, &cb) && cb==2))
            goto finish;

        UINT8 opc = rd_buf[0];
        if (opc==0xff && (rd_buf[1]&0xf8)==0xd0)
        {
            /* "call gpr" - call a sub-handler */
            DEBUG_VALUE reg_r;
            gpr_t call_reg = (gpr_t)(rd_buf[1]&0x07);

            if (DebugRegisters->GetValue(reg_ids[call_reg], &reg_r)!=S_OK)
                goto finish;

            /* set call handler bp */
            if (!hndl_bp_set)
            {
                if (DebugRegisters->GetValue(reg_ids[eip], &eip_r)!=S_OK)
                    goto finish;

                sprintf(cmd, "ba[0n%d] e1 0x%08X", BP_ID_BASE+1, eip_r.I32);
                if (DebugControl->Execute(
                    DEBUG_OUTCTL_IGNORE, cmd, DEBUG_EXECUTE_NOT_LOGGED)!=S_OK)
                    goto finish;

                hndl_bp_set=TRUE;
            }

            if (*p_out_len >= tab_len)
            {
                /* table to small - reallocate */
                size_t to_alloc = sizeof(def_out_tab[0])*tab_len+
                    sizeof(def_out_tab);
                UINT32 *p_alloc = (UINT32*)malloc(to_alloc);
                if (p_alloc) {
                    *pp_out = p_alloc;
                    tab_len = to_alloc/sizeof(def_out_tab[0]);
                } else goto finish;
            }
            (*pp_out)[(*p_out_len)++]=reg_r.I32;

            /* skip the actual call */
            if (DebugRegisters->GetValue(reg_ids[eip], &eip_r)!=S_OK)
                goto finish;
            eip_r.I32 += 2;
            if (DebugRegisters->SetValue(reg_ids[eip], &eip_r)!=S_OK)
                goto finish;
        } else
        if (opc==0xe8)
        {
            /* "call rel" - used to get eip addr; need to be traced into */
            if (DebugControl->Execute(
                    DEBUG_OUTCTL_IGNORE, "t", DEBUG_EXECUTE_NOT_LOGGED)!=S_OK ||
                DebugControl->WaitForEvent(0, INFINITE)!=S_OK) goto finish;
        } else break;
    }

    ret=TRUE;
finish:
    if (!ret) {
        free_init_hndls(*pp_out);
        *pp_out = NULL;
        *p_out_len = 0;
    }
    if (rest_need) {
        /* restore the processor context */
        if (DebugRegisters->SetValues(regs_n, reg_ids, 0, context)!=S_OK) {
            warn_dbgprintf("get_init_hndls() can not restore original context; "
                "the target application may crash!\n");
        }
    }
    if (bps_clear) {
        sprintf(cmd, "bc[0n%d]; bc[0n%d]", BP_ID_BASE, BP_ID_BASE+1);
        if (DebugControl->Execute(
            DEBUG_OUTCTL_IGNORE, cmd, DEBUG_EXECUTE_NOT_LOGGED)!=S_OK)
        {
            warn_dbgprintf(
                "get_init_hndls() unable to clear working breakpoints!\n");
        }
    }
    if (DebugControl) DebugControl->Release();
    if (DebugRegisters) DebugRegisters->Release();

    return ret;
}

/* Borland init table */
typedef struct _init_tab_t
{
    UINT32 is_present;
    UINT32 hndls_tab;   /* points to hndls_tab_t */
} init_tab_t;

typedef struct _hndls_tab_t
{
    UINT32 constr;
    UINT32 destr;
} hndls_tab_t;

/* Dump fixed init table pointed by 'init_tab_addr' into file with name 'fname'.
   Base addr of the fixed code will be set to 'code_base'.
 */
BOOL dump_init_tab(ULONG64 init_tab_addr, ULONG64 code_base, const char *fname)
{
    BOOL ret=FALSE, f_err=FALSE;

    FILE *fh = fopen(fname, "wb");
    if (!fh) {
        err_dbgprintf("File opening error: %s\n", strerror(errno));
        goto err;
    }

    /* set the code base in the init code */
    set_32uint_le(&init_code[BASE_INIT_CODE_OFF], (UINT32)code_base);

    if (f_err=(fwrite(init_code, 1, sizeof(init_code), fh)!=sizeof(init_code)))
        goto err;

    ULONG cb;
    init_tab_t init_tab;

    if (!(read_memory(init_tab_addr, &init_tab, sizeof(init_tab), &cb) &&
        cb==sizeof(init_tab))) goto err;

    if (!get_32uint_le(&init_tab.is_present)) {
        info_dbgprintf("Handlers are not present in the init table at 0x%p\n",
            init_tab_addr);
        goto no_err;
    }

    hndls_tab_t hndls_tab;
    ULONG64 hndls_tab_addr = DEBUG_EXTEND64(get_32uint_le(&init_tab.hndls_tab));
    if (!(read_memory(hndls_tab_addr, &hndls_tab, sizeof(hndls_tab), &cb) && cb==
        sizeof(hndls_tab))) goto err;

    ULONG64 constr_addr = DEBUG_EXTEND64(get_32uint_le(&hndls_tab.constr));
    ULONG64 destr_addr = DEBUG_EXTEND64(get_32uint_le(&hndls_tab.destr));

    UINT32 *p_hndls;
    size_t constr_n, destr_n, i;

    hndls_tab_t sub_hndls_pair;
    sub_hndls_pair.destr=0;

    /* set sub-constructors pointers */
    if (!get_init_hndls(constr_addr, &p_hndls, &constr_n)) goto err;
    for (i=0; i<=constr_n; i++)
    {
        /* update addresses relative to the code base */
        if (i==constr_n) {
            sub_hndls_pair.constr=0;
        } else {
            set_32uint_le(
                &sub_hndls_pair.constr, (UINT32)(p_hndls[i]-(UINT32)code_base));
        }
        if (f_err=(fwrite(&sub_hndls_pair, 1,
            sizeof(sub_hndls_pair), fh)!=sizeof(sub_hndls_pair))) goto err;
    }
    free_init_hndls(p_hndls);

    /* set sub-destructors pointers */
    if (!get_init_hndls(destr_addr, &p_hndls, &destr_n)) goto err;

    sub_hndls_pair.constr=0;
    sub_hndls_pair.destr=0;
    for (i=constr_n; i<destr_n; i++) {
        if (f_err=(fwrite(&sub_hndls_pair, 1,
            sizeof(sub_hndls_pair), fh)!=sizeof(sub_hndls_pair))) goto err;
    }

    if (f_err=fseek(fh, sizeof(init_code)+sizeof(UINT32), SEEK_SET)) goto err;

    for (i=0; i<destr_n; i++)
    {
        /* update addresses relative to the code base */
        UINT32 destr_rel = p_hndls[i]-(UINT32)code_base;
        if (f_err=(fwrite(&destr_rel, 1, sizeof(destr_rel), fh)!=
            sizeof(destr_rel) || fseek(fh, sizeof(UINT32), SEEK_CUR))) goto err;
    }
    free_init_hndls(p_hndls);

no_err:
    ret=TRUE;
err:
    if (f_err) err_dbgprintf("File access error\n");
    if (fh) fclose(fh);
    return ret;
}

/* Patch init table previously dumped by dump_init_tab() */
BOOL patch_init_tab(ULONG64 init_tab_addr, ULONG64 code_base, const char *fname)
{
    BOOL ret=FALSE, f_err=FALSE;

    FILE *fh = fopen(fname, "rb");
    if (!fh) {
        err_dbgprintf("File opening error: %s\n", strerror(errno));
        goto finish;
    }

    ULONG cb;
    init_tab_t init_tab;

    if (!(read_memory(init_tab_addr, &init_tab, sizeof(init_tab), &cb) &&
        cb==sizeof(init_tab))) goto finish;

    /* patch handlers addresses */
    hndls_tab_t hndls_tab;
    set_32uint_le(&hndls_tab.constr, (UINT32)(code_base+CONSTR_START_OFF));
    set_32uint_le(&hndls_tab.destr, (UINT32)(code_base+DESTR_START_OFF));

    ULONG64 hndls_tab_addr = DEBUG_EXTEND64(get_32uint_le(&init_tab.hndls_tab));
    if (!(write_memory(hndls_tab_addr, &hndls_tab, sizeof(hndls_tab), &cb) &&
        cb==sizeof(hndls_tab))) goto finish;

    /* ... and load the code into memory */
    cpy_ret_t rc = file2mem(code_base, fh, 0);
    if (f_err=(rc==cpy_src_err)) goto finish;
    else
    if (rc==cpy_dst_err) {
        err_dbgprintf("Memory access error\n");
        goto finish;
    }

    ret=TRUE;
finish:
    if (f_err) err_dbgprintf("File access error\n");
    if (fh) fclose(fh);
    return ret;
}

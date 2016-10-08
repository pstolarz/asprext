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
#include <stdarg.h>

/*
    TLS and dbg client related funcs
 */
static DWORD tls_i=TLS_OUT_OF_INDEXES;

void set_tls_i(DWORD tls_i) {
    ::tls_i=tls_i;
}

DWORD get_tls_i(void) {
    return tls_i;
}

void set_client(PDEBUG_CLIENT4 Client) {
    if (tls_i!=TLS_OUT_OF_INDEXES) TlsSetValue(tls_i, Client);
}

PDEBUG_CLIENT4 get_client(void) {
    return (PDEBUG_CLIENT4)
        (tls_i!=TLS_OUT_OF_INDEXES ? TlsGetValue(tls_i) : NULL);
}

static void vdbgprintf(
    ULONG ctrl, ULONG mask, const char *pc_pref, const char *format, va_list args)
{
    IDebugControl *DebugControl=NULL;

    PDEBUG_CLIENT4 Client;
    if (!(Client=get_client())) goto finish;

    if (Client->QueryInterface(
        __uuidof(IDebugControl), (void **)&DebugControl)!=S_OK) goto finish;

    if (pc_pref) DebugControl->ControlledOutput(ctrl, mask, "%s: ", pc_pref);
    DebugControl->ControlledOutputVaList(ctrl, mask, format, args);

finish:
    if (DebugControl) DebugControl->Release();
    return;
}

#define DBGPRNT_METHOD(name, pref)                    \
    void name(const char *format, ...) {              \
        va_list args;                                 \
        va_start(args, format);                       \
        vdbgprintf(DBGPRNT_OUTCTL_FLAGS,              \
            DBGPRNT_OUTPUT_FLAGS, pref, format, args);\
        va_end(args);                                 \
    }

DBGPRNT_METHOD(dbgprintf, NULL)
DBGPRNT_METHOD(dbg_dbgprintf, "DBG")
DBGPRNT_METHOD(info_dbgprintf, "INFO")
DBGPRNT_METHOD(warn_dbgprintf, "WARN")
DBGPRNT_METHOD(err_dbgprintf, "ERR")

/*
    memory access funcs
 */
#define MEMACCESS_METHOD(name, func)                                         \
    ULONG name(ULONG64 addr, PVOID p_buf, ULONG buf_sz, PULONG p_cb)         \
    {                                                                        \
        ULONG ret=FALSE;                                                     \
        IDebugDataSpaces *DebugDataSpaces=NULL;                              \
                                                                             \
        PDEBUG_CLIENT4 Client;                                               \
        if (Client=get_client()) {                                           \
            if (Client->QueryInterface(__uuidof(IDebugDataSpaces),           \
                (void **)&DebugDataSpaces)==S_OK) {                          \
                ret=(DebugDataSpaces->func(addr, p_buf, buf_sz, p_cb)==S_OK);\
            }                                                                \
        }                                                                    \
                                                                             \
        if (DebugDataSpaces) DebugDataSpaces->Release();                     \
        return ret;                                                          \
    }

/* WdbgExts ReadMemory(), WriteMemory() analogous */
MEMACCESS_METHOD(read_memory, ReadVirtual)
MEMACCESS_METHOD(write_memory, WriteVirtual)

/* WdbgExts GetExpressionEx() analogous */
BOOL get_expression(PCSTR pc_expr, ULONG64 *p_val, PCSTR *ppc_rem)
{
    BOOL ret=FALSE;
    IDebugControl *DebugControl=NULL;

    PDEBUG_CLIENT4 Client;
    if (!(Client=get_client())) goto finish;

    if ((Client->QueryInterface(
        __uuidof(IDebugControl), (void **)&DebugControl))!=S_OK) goto finish;

    ULONG rem_i;
    DEBUG_VALUE val;
    if (DebugControl->Evaluate(
        pc_expr, DEBUG_VALUE_INT64, &val, &rem_i)!=S_OK) goto finish;

    if (ppc_rem) {
        for (pc_expr+=rem_i; isspace(*pc_expr); pc_expr++);
        *ppc_rem = pc_expr;
    }
    *p_val = (ULONG64)val.I64;

    ret=TRUE;
finish:
    if (DebugControl) DebugControl->Release();
    return ret;
}

/* Copy target's string 'targ_in_addr' into local buf 'pc_out_buf' ('out_buf_len'
   long, which should be a divisible by 4). The func checks if the copied string
   fits into the buffer and returns FALSE if the buffer is too small for the
   string. 'end_chr' specifies end-of-string char (by default 0). Copied string
   is NULL terminated w/o the end-of-string char.
 */
BOOL string_cpy_lt(
    char *pc_out_buf, ULONG64 targ_in_addr, size_t out_buf_len, int end_chr)
{
    BOOL ret=FALSE;
    UINT32 dw;
    char *pc_dw = (char*)&dw;

    for (size_t i=0; i<out_buf_len; targ_in_addr+=sizeof(dw), i+=sizeof(dw))
    {
        ULONG cb;
        if (!(read_memory(targ_in_addr, &dw, sizeof(dw), &cb) &&
            cb==sizeof(dw))) goto err;

        for (size_t j=0; j<sizeof(dw); j++)
            if ((pc_out_buf[i+j]=pc_dw[j])==(char)end_chr) {
                pc_out_buf[i+j]=0;
                goto no_err;
            }
    }

    /* string to long (end-of-string char absent) */
    goto err;

no_err:
    ret=TRUE;
err:
    return ret;
}

/* Compare local string 'pc_str1' with target's string 'str2_addr' */
int string_cmp_lt(const char *pc_str1, ULONG64 str2_addr)
{
    int ret=-1;
    UINT32 dw;
    char *pc_dw = (char*)&dw;

    for (size_t i=0;; str2_addr+=sizeof(dw), i+=sizeof(dw))
    {
        ULONG cb;
        if (!(read_memory(str2_addr, &dw, sizeof(dw), &cb) &&
            cb==sizeof(dw))) break;

        for (size_t j=0; j<sizeof(dw); j++) {
            if (ret=pc_str1[i+j]-pc_dw[j]) goto finish;
            if (!pc_dw[j]) goto finish;
        }
    }

finish:
    return ret;
}

/* Reverse memchr(): look for a byte with a value other than 'val' */
void *rmemchr(const void *ptr, int val, size_t num)
{
    void *ret=NULL;

    for (size_t i=0; i<num; i++)
        if (((char*)ptr)[i]!=val) { ret=(void*)&(((char*)ptr)[i]); break; }

    return ret;
}

/* Get module name from module's full file name pointed by 'pc_name'. 'p_len'
   will get module's length.
 */
char *get_mod_name(const char *pc_name, size_t *p_len)
{
    const char *pc_mod = pc_name;

    const char *sl = strrchr(pc_mod, '/');
    const char *bsl = strrchr(pc_mod, '\\');
    const char *col = strrchr(pc_mod, ':');

    if (bsl) pc_mod=bsl+1;
    else
    if (sl) pc_mod=sl+1;
    else
    if (col) pc_mod=col+1;

    const char *dot = strrchr(pc_mod, '.');
    *p_len = (dot ? dot-pc_mod : strlen(pc_mod));

    return (char*)pc_mod;
}

/* bytes to hex conversion */
void bts2hex(const unsigned char *in, size_t in_len, char *out)
{
    static char HEX_DIGS[] = "0123456789abcdef";
    size_t i,j;

    for (i=j=0; i<in_len; i++) {
        out[j++] = HEX_DIGS[in[i]>>4];
        out[j++] = HEX_DIGS[in[i]&0x0f];
    }
    out[j]=0;
}

/* Copy memory starting from address 'mem_addr' with 'sz' size into file 'f'
   (from its current position).
 */
cpy_ret_t mem2file(FILE *f, ULONG64 mem_addr, ULONG sz)
{
    char read_buf[0x400];
    cpy_ret_t ret = cpy_ok;

    for (ULONG off=0; sz;)
    {
        ULONG cb;
        ULONG read_sz = (sz<=sizeof(read_buf) ? sz : sizeof(read_buf));

        if (!(read_memory(mem_addr+off, read_buf, read_sz, &cb) && cb==read_sz))
            { ret=cpy_src_err; goto finish; }
        if (fwrite(read_buf, 1, read_sz, f)!=read_sz)
            { ret=cpy_dst_err; goto finish; }

        sz -= read_sz;
        off += read_sz;
    }

finish:
    return ret;
}

/* Copy a file (from its current position) into memory (at 'mem_addr' address)
   with size 'sz'. If 'sz' is zero copy up to the end of the file.
 */
cpy_ret_t file2mem(ULONG64 mem_addr, FILE *f, size_t sz)
{
    size_t off=0;
    char read_buf[0x400];
    BOOL b_loopcnt=TRUE;
    cpy_ret_t ret = cpy_ok;

    for (size_t to_proc=sz; b_loopcnt && (!sz || to_proc);)
    {
        ULONG cb;
        size_t read_sz = (!sz ||
            (to_proc>sizeof(read_buf)) ? sizeof(read_buf) : to_proc);

        if ((cb=fread(read_buf, 1, read_sz, f))!=read_sz) {
            if (sz) { ret=cpy_src_err; break; }
            else { read_sz=cb; b_loopcnt=FALSE; }
        }

        if (!(write_memory(mem_addr+off, read_buf, read_sz, &cb) &&
            cb==read_sz))
        {
            ret=cpy_dst_err;
            goto finish;
        }

        to_proc-=read_sz;
        off+=read_sz;
    }

finish:
    return ret;
}

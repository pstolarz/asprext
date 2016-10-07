/*
   Copyright (c) 2016 Piotr Stolarz
   asprext: ASProtect reverse engineering & analysis WinDbg extension

   Distributed under the GNU General Public License (the License)
   see accompanying file LICENSE for details.

   This software is distributed WITHOUT ANY WARRANTY; without even the
   implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
   See the License for more information.
 */

#ifndef __ASPREXT_COMMON_H__
#define __ASPREXT_COMMON_H__

#include <windows.h>
#include <winnt.h>
#include <stdio.h>
#include <dbgeng.h>
#include <stdint.h>
#include "endian.h"
#include "rdflags.h"

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE !FALSE
#endif

#ifndef NULL
#define NULL 0
#endif

#define ARRAY_SZ(a) (sizeof((a))/sizeof((a)[0]))

#define RNDUP(x, d) ((d)*(((x)+((d)-1))/(d)))
/* special cases */
#define RNDUP_W(x)  ((((x)+1)>>1)<<1)
#define RNDUP_DW(x) ((((x)+3)>>2)<<2)

/* TLS and dbg client related funcs */
void set_tls_i(DWORD tls_i);
DWORD get_tls_i(void);

void set_client(PDEBUG_CLIENT4 Client);
PDEBUG_CLIENT4 get_client(void);

#define DBGPRNT_OUTCTL_FLAGS DEBUG_OUTCTL_ALL_CLIENTS
#define DBGPRNT_OUTPUT_FLAGS DEBUG_OUTPUT_NORMAL

/* dbg printf related funcs */
void dbgprintf(const char *format, ...);
void dbg_dbgprintf(const char *format, ...);
void info_dbgprintf(const char *format, ...);
void warn_dbgprintf(const char *format, ...);
void err_dbgprintf(const char *format, ...);

/* memory access funcs */
ULONG read_memory(ULONG64 addr, PVOID p_buf, ULONG buf_sz, PULONG p_cb);
ULONG write_memory(ULONG64 addr, PVOID p_buf, ULONG buf_sz, PULONG p_cb);

/* expression eval */
BOOL get_expression(PCSTR pc_expr, ULONG64 *p_val, PCSTR *ppc_rem);

BOOL string_cpy_lt(
    char *pc_out_buf, ULONG64 targ_in_addr, size_t out_buf_len, int end_chr=0);

int string_cmp_lt(const char *pc_str1, ULONG64 str2_addr);

void *rmemchr(const void *ptr, int val, size_t num);

char *get_mod_name(const char *pc_name, size_t *p_len);

void bts2hex(const unsigned char *in, size_t in_len, char *out);

typedef enum _cpy_ret_t
{
    cpy_ok = 0,     /* success */
    cpy_src_err,    /* source access error */
    cpy_dst_err     /* destination access error */
} cpy_ret_t;

cpy_ret_t mem2file(FILE *f, ULONG64 mem_addr, ULONG sz);
cpy_ret_t file2mem(ULONG64 mem_addr, FILE *f, size_t sz);

#endif /* __ASPREXT_COMMON_H__ */

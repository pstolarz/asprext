/*
   Copyright (c) 2016 Piotr Stolarz
   asprext: ASProtect reverse engineering & analysis WinDbg extension

   Distributed under the GNU General Public License (the License)
   see accompanying file LICENSE for details.

   This software is distributed WITHOUT ANY WARRANTY; without even the
   implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
   See the License for more information.
 */

#ifndef __ASPREXT_OEP_ASPR_H__
#define __ASPREXT_OEP_ASPR_H__

#define GETOEP_DUMPEXT      0x01U

void print_oep_addr(ULONG64 oep_env_addr, DWORD flags);

void print_poly_buf_emuls(ULONG64 oep_env_addr);

BOOL trace_poly_buf(ULONG64 poly_buf_env_addr, BOOL b_disasm=TRUE);

#endif /* __ASPREXT_OEP_ASPR_H__ */

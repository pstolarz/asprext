/*
   Copyright (c) 2016 Piotr Stolarz
   asprext: ASProtect reverse engineering & analysis WinDbg extension

   Distributed under the GNU General Public License (the License)
   see accompanying file LICENSE for details.

   This software is distributed WITHOUT ANY WARRANTY; without even the
   implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
   See the License for more information.
 */

#ifndef __ASPREXT_ASPR_VM_H__
#define __ASPREXT_ASPR_VM_H__

/* print VM context flags */
#define PRNCTX_LINE         0x01U       /* 1 line output */

void print_vmctx(ULONG64 vmctx_addr, ULONG64 vmin_addr, DWORD flags);

void vm_disasm(ULONG64 vmin_addr);

#endif /* __ASPREXT_ASPR_VM_H__ */

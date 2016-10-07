/*
   Copyright (c) 2016 Piotr Stolarz
   asprext: ASProtect reverse engineering & analysis WinDbg extension

   Distributed under the GNU General Public License (the License)
   see accompanying file LICENSE for details.

   This software is distributed WITHOUT ANY WARRANTY; without even the
   implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
   See the License for more information.
 */

#ifndef __ASPREXT_INIT_ASPR_H__
#define __ASPREXT_INIT_ASPR_H__

BOOL dump_init_tab(ULONG64 init_tab_addr, ULONG64 code_base, const char *fname);
BOOL patch_init_tab(ULONG64 init_tab_addr, ULONG64 code_base, const char *fname);

#endif /* __ASPREXT_INIT_ASPR_H__ */

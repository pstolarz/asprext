/*
   Copyright (c) 2016 Piotr Stolarz
   asprext: ASProtect reverse engineering & analysis WinDbg extension

   Distributed under the GNU General Public License (the License)
   see accompanying file LICENSE for details.

   This software is distributed WITHOUT ANY WARRANTY; without even the
   implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
   See the License for more information.
 */

#ifndef __ASPREXT_CONFIG_H__
#define __ASPREXT_CONFIG_H__

/* supported ASPR versions */
typedef enum _aspr_ver_t
{
    aspr_ver_min,

    aspr_unknown=aspr_ver_min,

    /* 1.63-1.70 */
    aspr_1_6X,

    aspr_ver_max = aspr_1_6X
} aspr_ver_t;


void set_version(aspr_ver_t ver);
aspr_ver_t get_version(void);

#endif /* __ASPREXT_CONFIG_H__ */

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
#include "config.h"

/* set with default */
static aspr_ver_t version = aspr_1_6X;   // aspr_unknown;

/* set handled ASPR version */
void set_version(aspr_ver_t ver)
{
    version = ver;
}

/* get handled ASPR version */
aspr_ver_t get_version(void)
{
    return version;
}

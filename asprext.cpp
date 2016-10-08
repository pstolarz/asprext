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
#include "vm_aspr.h"
#include "imports.h"
#include "oep_aspr.h"
#include "init_aspr.h"

/* DLL entry point */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    BOOL ret=TRUE;

    switch(fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        set_tls_i(TlsAlloc());
        ret = (get_tls_i()!=TLS_OUT_OF_INDEXES);
        break;

    case DLL_PROCESS_DETACH:
        if (get_tls_i()!=TLS_OUT_OF_INDEXES) TlsFree(get_tls_i());
        break;
    }

    return ret;
}

/* Extension initialization */
HRESULT CALLBACK
DebugExtensionInitialize(PULONG Version, PULONG Flags)
{
    *Version = DEBUG_EXTENSION_VERSION(1, 0);
    *Flags = 0;

    return S_OK;
}

/* Recognize command string 'p_cmd' in arguments input 'args'. Min recognized
   length of the command is passed by 'min_len'. If command has been recognized
   TRUE is returned and 'p_args' will point just after the recognized command
   in 'args'.
 */
static BOOL is_cmd(PCSTR args, const char *p_cmd, size_t min_len, PCSTR *p_args)
{
    BOOL ret=FALSE;

    *p_args=args;

    size_t i, cmd_len;
    for (i=0; isspace(args[i]); i++);
    for (cmd_len=0; args[i+cmd_len] && !isspace(args[i+cmd_len]); cmd_len++);

    BOOL cmd_match = (!cmd_len ? TRUE : !strncmp(&args[i], p_cmd, cmd_len));

    if (!min_len && !cmd_match) {
        /* for default command and not matching input: if the input indicates
           the command's flags (staring by '-') then the command matches, since
           it seems it has been omitted; else some other command is provided -
           return FALSE */
        ret = args[i]=='-';
    } else
    if (cmd_match && cmd_len>=min_len) {
        i += cmd_len;
        *p_args = &args[i];
        ret=TRUE;
    }
    return ret;
}

/* aspr_vmctx_dump [-l] vm_ctx_addr [vm_in_addr] */
HRESULT CALLBACK
aspr_vmctx_dump(PDEBUG_CLIENT4 Client, PCSTR args)
{
    HRESULT ret=E_FAIL;
    set_client(Client);

    ULONG64 vmctx_addr, vmin_addr;
    flag_desc_t flags_dsc[] = {{'l', FALSE}, {0}};

    DWORD flags = 0;
    size_t rd_sz = read_flags(args, flags_dsc);
    args += rd_sz;

    if (flags_dsc[0].is_pres) flags|=PRNCTX_LINE;

    /* read mandatory vm_ctx addr & optional vm_in */
    if (!get_expression(args, &vmctx_addr, &args)) goto finish;
    if (!get_expression(args, &vmin_addr, &args)) vmin_addr=0;

    print_vmctx(vmctx_addr, vmin_addr, flags);

    ret=S_OK;
finish:
    return ret;
}

/* aspr_vmin_disasm vm_in_addr */
HRESULT CALLBACK
aspr_vmin_disasm(PDEBUG_CLIENT4 Client, PCSTR args)
{
    HRESULT ret=E_FAIL;
    set_client(Client);

    /* read mandatory vm_in addr */
    ULONG64 vmin_addr;
    if (!get_expression(args, &vmin_addr, &args)) goto finish;

    vm_disasm(vmin_addr);

    ret=S_OK;
finish:
    return ret;
}

/* aspr_imports family of commands */
HRESULT CALLBACK
aspr_imports(PDEBUG_CLIENT4 Client, PCSTR args)
{
    HRESULT ret=E_FAIL;
    set_client(Client);

    if (is_cmd(args, "load", 1, &args))
    {
        DWORD flags=0;
        flag_desc_t flags_dsc[] = {{'e', FALSE}, {0}};

        size_t rd_sz = read_flags(args, flags_dsc);
        args += rd_sz;

        if (flags_dsc[0].is_pres) flags|=LDIMPS_AIP_ENV_ADDR;

        ULONG64 in_addr;
        if (!get_expression(args, &in_addr, &args)) goto finish;

        load_imports(in_addr, flags);
    } else
    if (is_cmd(args, "unload", 1, &args)) {
        unload_imports();
    } else
    if (is_cmd(args, "print", 0, &args))
    {
        DWORD flags=0;
        flag_desc_t flags_dsc[] = {{'x', FALSE}, {0}};
        read_flags(args, flags_dsc);

        if (flags_dsc[0].is_pres) print_imp_spec();
        else print_imports();
    }

    ret=S_OK;
finish:
    return ret;
}

/* aspr_ipatch family of commands */
HRESULT CALLBACK
aspr_ipatch(PDEBUG_CLIENT4 Client, PCSTR args)
{
    HRESULT ret=E_FAIL;
    set_client(Client);

    if (is_cmd(args, "load", 1, &args))
    {
        DWORD flags=0;
        flag_desc_t flags_dsc[] = {{'1', FALSE}, {0}};

        size_t rd_sz = read_flags(args, flags_dsc);
        args += rd_sz;

        if (flags_dsc[0].is_pres) flags|=LDPTCHS_1_DUPL;

        ULONG64 aip_env_addr, chk_mem_addr;
        if (!get_expression(args, &aip_env_addr, &args)) goto finish;
        if (!get_expression(args, &chk_mem_addr, &args)) goto finish;

        load_patches(aip_env_addr, chk_mem_addr, flags);
    } else
    if (is_cmd(args, "unload", 1, &args)) {
        unload_patches();
    } else
    if (is_cmd(args, "apply", 1, &args))
    {
        DWORD flags=0;
        flag_desc_t flags_dsc[] = {{'i', FALSE}, {'v', FALSE}, {0}};

        size_t rd_sz = read_flags(args, flags_dsc);
        args += rd_sz;

        if (flags_dsc[0].is_pres) flags|=APLPTCHS_IAT_PATCH;
        if (flags_dsc[1].is_pres) flags|=APLPTCHS_VERBOSE;

        apply_patches(flags);
    } else
    if (is_cmd(args, "print", 0, &args)) {
        print_patches();
    }

    ret=S_OK;
finish:
    return ret;
}

/* aspr_init family of commands */
HRESULT CALLBACK
aspr_init(PDEBUG_CLIENT4 Client, PCSTR args)
{
    HRESULT ret=E_FAIL;
    set_client(Client);

    if (is_cmd(args, "dump", 1, &args))
    {
        size_t i;
        ULONG64 init_tab_addr, code_base;

        if (!get_expression(args, &init_tab_addr, &args)) goto finish;
        if (!get_expression(args, &code_base, &args)) goto finish;

        for (i=0; isspace(args[i]); i++);
        if (!args[i]) goto finish;

        if (!dump_init_tab(init_tab_addr, code_base, &args[i])) goto finish;
        info_dbgprintf(
            "Borland init table code successfully dumped to file %s\n", &args[i]);
    } else
    if (is_cmd(args, "patch", 1, &args))
    {
        size_t i;
        ULONG64 init_tab_addr, code_base;

        if (!get_expression(args, &init_tab_addr, &args)) goto finish;
        if (!get_expression(args, &code_base, &args)) goto finish;

        for (i=0; isspace(args[i]); i++);
        if (!args[i]) goto finish;

        if (!patch_init_tab(init_tab_addr, code_base, &args[i])) goto finish;
        info_dbgprintf("Borland init table code successfully patched\n");
    } goto finish;

    ret=S_OK;
finish:
    return ret;
}

/* aspr_oep [-x] oep_env_addr */
HRESULT CALLBACK
aspr_oep(PDEBUG_CLIENT4 Client, PCSTR args)
{
    HRESULT ret=E_FAIL;
    set_client(Client);

    DWORD flags=0;
    flag_desc_t flags_dsc[] = {{'x', FALSE}, {0}};

    size_t rd_sz = read_flags(args, flags_dsc);
    args += rd_sz;

    if (flags_dsc[0].is_pres) flags|=GETOEP_DUMPEXT;

    ULONG64 oep_env_addr;
    if (!get_expression(args, &oep_env_addr, &args)) goto finish;

    print_oep_addr(oep_env_addr, flags);

    ret=S_OK;
finish:
    return ret;
}

/* TODO */
HRESULT CALLBACK
aspr_poly_buf(PDEBUG_CLIENT4 Client, PCSTR args)
{
    HRESULT ret=E_FAIL;
    set_client(Client);

    ULONG64 poly_buf_env_addr, base_addr;
    if (!get_expression(args, &poly_buf_env_addr, &args)) goto finish;

    trace_poly_buf(poly_buf_env_addr);

    ret=S_OK;
finish:
    return ret;
}

/* help info */
HRESULT CALLBACK
help(PDEBUG_CLIENT4 Client, PCSTR args)
{
    set_client(Client);

    dbgprintf(
"asprext: ASProtect reverse engineering & analysis utils\n\n"
"aspr_vmctx_dump [-l] vm_ctx_addr [vm_in_addr]\n"
"    Show the VM context under an address vm_ctx_addr. If an address of the\n"
"    VM input is provided: vm_in_addr, the currently executed opcode will be\n"
"    disassembled.\n"
"    -l: single line output\n\n"
"aspr_vmin_disasm vm_in_addr\n"
"    Disassembly opcodes of the VM input from an address vm_in_addr.\n\n"
"aspr_imports load [-e] addr\n"
"    Load imports. addr is an address of ASPR AIP environment or ASPR imports\n"
"    description struct.\n"
"    -e: addr points to the ASPR AIP environment struct\n"
"aspr_imports unload\n"
"    Unload previously loaded imports\n"
"aspr_imports [print] [-x]\n"
"    Show loaded imports\n"
"    -x: Display loaded imports in the dumpext extension's imports spec. format\n\n"
"aspr_ipatch load [-1] aip_env_addr chk_mem_addr\n"
"    Load list of import patches. aip_env_addr is an address of ASPR AIP\n"
"    environment struct. chk_mem_addr identifies start of memory range used for\n"
"    calculation of the seed. The seed is utilized for computation of the ids of\n"
"    imported libraries and their procs. To successfully generate proper patches\n"
"    the loaded imports spec. must contain modules with non-destroyed IAT addresses.\n"
"    -1: Some compilers (e.g. Delphi) may produce duplicated imports in their\n"
"        imports dir. In this case there is possible to resolve a patch to many\n"
"        equivalent alternatives. This flag causes to set a patch for the first\n"
"        import in the set of duplicates.\n"
"aspr_ipatch unload\n"
"    Unload previously loaded patches list\n"
"aspr_ipatch [print]\n"
"    Show loaded patches list\n"
"aspr_ipatch apply [-i] [-v]\n"
"    Apply loaded patches into memory\n"
"    -i: additionally apply patches to the module's IAT table\n"
"    -v: verbose mode\n\n"
"aspr_init dump init_tab_addr code_base file_name\n"
"    Dump fixed Borland init table code of the table located at the address\n"
"    init_tab_addr to the file file_name. Base of the fixed code shall be set to\n"
"    base_code.\n"
"aspr_init patch init_tab_addr code_base file_name\n"
"    Patch the init code previously dumped by the \"dump\" command. Parameters\n"
"    shall be the same as for the \"dump\" command\n\n"
"aspr_oep [-x] oep_env_addr\n"
"    Print the Original Entry Point. oep_env_addr is an address to the OEP environment.\n"
"    -x: Display OEP RVA in the format used by the dumpext extension library\n\n"
"help\n"
"    Display this help.\n");

    return S_OK;
}

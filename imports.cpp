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
#include "aip_aspr.h"

#define RVA2ADDR(rva,mb) ((rva) ? ((rva)+(mb)) : 0)
#define ADDR2RVA(adr,mb) ((DWORD)((adr) ? ((adr)-(mb)) : 0))

/* loaded patches */
static struct
{
    aspr_ver_t ver;         /* ver of ASPR imports are loaded */
    UINT nptch;             /* number of patches in the list */
    imp_patch_t *p_ptchs;   /* patches list; NULL: parches not loaded */
} ld_ptchs = {(aspr_ver_t)0, 0, NULL};

/* loaded importing mods */
static struct
{
    aspr_ver_t ver;         /* ver of ASPR patches are loaded */
    UINT nmods;             /* number of importing mods in the list */
    mod_imp_t *p_mods;      /* importing mods list; NULL" import not loaded */
} ld_mods = {(aspr_ver_t)0, 0, NULL};

/* Get loaded imports */
void get_loaded_imports(aspr_ver_t *p_ver, mod_imp_t **pp_mods, UINT *p_nmods)
{
    *p_ver = ld_mods.ver;
    *pp_mods = ld_mods.p_mods;
    *p_nmods = ld_mods.nmods;
}

/* Load ASPR protected imports */
void load_imports(ULONG64 in_addr, DWORD flags)
{
    aspr_ver_t ver = get_version();

    UINT nmods=0;
    mod_imp_t *p_mods=NULL;

    if (get_imports(ver, in_addr,
        (flags & LDIMPS_AIP_ENV_ADDR ? TRUE : FALSE), &p_mods, &nmods))
    {
        mod_imp_t *p_ld_mods=ld_mods.p_mods;

        ld_mods.ver = ver;
        ld_mods.nmods = nmods;
        ld_mods.p_mods = p_mods;
        free_imports(p_ld_mods);

        info_dbgprintf("Imports loaded\n");
    } else {
        err_dbgprintf("Can't load imports\n");
    }
}

/* Unload imports */
void unload_imports()
{
    if (ld_mods.p_mods)
    {
        mod_imp_t *p_ld_mods=ld_mods.p_mods;

        ld_mods.nmods = 0;
        ld_mods.p_mods = NULL;
        free_imports(p_ld_mods);
    }
}

/* Print loaded imports */
void print_imports()
{
    if (ld_mods.p_mods)
    {
        BOOL res_stl=FALSE;
        for (mod_imp_t *p_lib=ld_mods.p_mods; p_lib; p_lib=p_lib->next)
        {
            dbgprintf("%s\n", p_lib->pc_mod_name);

            dbgprintf("  Module base: ");
            if (p_lib->mod_base) dbgprintf("0x%p\n", p_lib->mod_base);
            else dbgprintf("can't resolve\n");

            dbgprintf("  ASPR id:     0x%04X\n", p_lib->mod_id);
            dbgprintf("  IAT at:      0x%p\n", p_lib->iat_addr);
            dbgprintf(" Imports:\n");

            for (proc_imp_t *p_proc=p_lib->p_proc; p_proc; p_proc=p_proc->next)
            {
                dbgprintf("  %s\n", p_proc->pc_proc_name);

                dbgprintf("   Address: ");
                if (p_proc->proc_addr) dbgprintf("0x%p\n", p_proc->proc_addr);
                else dbgprintf("can't resolve\n");

                dbgprintf("   ASPR id: 0x%04X\n", p_proc->proc_id);

                dbgprintf("   Type:    ");
                switch (p_proc->tpy) {
                case imp_key1_noiat:
                    dbgprintf("Key 1 encrypted, no IAT\n");
                    break;
                case imp_key1_iat:
                    dbgprintf("Key 1 encrypted, IAT\n");
                    break;
                case imp_plain:
                    dbgprintf("Plain, IAT\n");
                    break;
                case imp_stl_re:
                    dbgprintf("Stolen raise except. proc, IAT\n");
                    break;
                case imp_stl_gpa:
                    if (ld_mods.ver==aspr_1_6X) {
                        dbgprintf("Stolen addr. resolver with CAPI, IAT\n");
                    } else {
                        /* aspr_unknown */
                        dbgprintf("Stolen addr. resolver type 2 with CAPI, IAT\n");
                    }
                    res_stl=TRUE;
                    break;
                case imp_stl_gpa2:
                    if (ld_mods.ver==aspr_1_6X) {
                        dbgprintf("Stolen addr. resolver type 2 with CAPI, IAT\n");
                    } else {
                        /* aspr_unknown */
                        dbgprintf("CAPI call, IAT\n");
                    }
                    res_stl=TRUE;
                    break;
                case imp_key2_iat:
                    dbgprintf("Key 2 encrypted, IAT\n");
                    break;
                case imp_key2_noiat:
                    dbgprintf("Key 2 encrypted, no IAT\n");
                    break;
                };
            }
        }

        if (res_stl) {
            dbgprintf("\n");
            warn_dbgprintf("Code may reference to the ASPR utility CAPIs, which "
                "may cause problems after unpacking\n");
        }
    } else
        info_dbgprintf("No loaded imports\n");
}

/* Print dumpext imports specification */
void print_imp_spec()
{
    ULONG64 mod_base=0;

    IDebugSymbols *DebugSymbols=NULL;
    if ((get_client()->QueryInterface(
        __uuidof(IDebugSymbols), (void **)&DebugSymbols)) != S_OK) goto finish;

    if (ld_mods.p_mods)
    {
        UINT lib_i=1;
        for (mod_imp_t *p_lib=ld_mods.p_mods; p_lib; p_lib=p_lib->next, lib_i++)
        {
            if (!mod_base) {
                if (DebugSymbols->GetModuleByOffset(
                    p_lib->iat_addr, 0, NULL, &mod_base)!=S_OK)
                {
                    err_dbgprintf("Addresses in the IAT table are corrupted\n");
                    goto finish;
                }
                dbgprintf("[imports]\n");
            }

            dbgprintf("%d = %s\n", lib_i, p_lib->pc_mod_name);
            dbgprintf("%d.iat_rva = 0x%08X\n",
                lib_i, ADDR2RVA(p_lib->iat_addr, mod_base));

            UINT proc_i=1;
            for (proc_imp_t *p_proc=p_lib->p_proc; p_proc;
                p_proc=p_proc->next, proc_i++)
            {
                if (p_proc->proc_ord!=(UINT32)-1) {
                    dbgprintf("%d.%d = #0x%04X\n",
                        lib_i, proc_i, p_proc->proc_ord);
                } else {
                    dbgprintf("%d.%d = %s\n",
                        lib_i, proc_i, p_proc->pc_proc_name);
                }
            }
        }
    }

finish:
    if (DebugSymbols) DebugSymbols->Release();
}

/* Load import patches */
void load_patches(ULONG64 aip_env_addr, ULONG64 chk_mem_addr, DWORD flags)
{
    aspr_ver_t ver = get_version();

    UINT nptch=0;
    imp_patch_t *p_ptchs=NULL;

    if(get_patches(ver, aip_env_addr, chk_mem_addr, flags, &p_ptchs, &nptch))
    {
        imp_patch_t *p_ld_ptchs=ld_ptchs.p_ptchs;

        ld_ptchs.ver = ver;
        ld_ptchs.nptch = nptch;
        ld_ptchs.p_ptchs = p_ptchs;
        free_patches(p_ld_ptchs);

        UINT emul_nptch=0;
        for (imp_patch_t *p_patch=ld_ptchs.p_ptchs; p_patch; p_patch=p_patch->next)
            if (p_patch->p_emul) emul_nptch++;

        info_dbgprintf("%d patches loaded = %d import patches + "
            "%d emulated opcode patches\n", nptch+emul_nptch, nptch, emul_nptch);
    } else {
        err_dbgprintf("Can't load patches\n");
    }
}

/* Unload import patches */
void unload_patches()
{
    if (ld_ptchs.p_ptchs)
    {
        imp_patch_t *p_ld_ptchs=ld_ptchs.p_ptchs;

        ld_ptchs.nptch = 0;
        ld_ptchs.p_ptchs = NULL;
        free_patches(p_ld_ptchs);
    }
}

/* Apply a signle patch */
static BOOL apply_patch(ULONG64 pt_addr, UINT8 *pt_data, UINT pt_len, BOOL b_logs)
{
    BOOL ret=FALSE;

    if (pt_len)
    {
        ULONG cb;
        if (!(write_memory(pt_addr, pt_data, pt_len, &cb) && cb==pt_len)) {
            if (b_logs) err_dbgprintf("Write memory error at 0x%p", pt_addr);
            goto finish;
        }
    } else {
        if (b_logs) err_dbgprintf("No patch data");
        goto finish;
    }

    if (b_logs) dbgprintf("OK");
    ret=TRUE;
finish:
    return ret;
}

/* Apply loaded patches */
void apply_patches(DWORD flags)
{
    UINT pt_i=0, pt_ok_i=0, ptiat_i=0, ptiat_ok_i=0;
    BOOL b_verb = (flags&APLPTCHS_VERBOSE)!=0;

    if (ld_ptchs.p_ptchs)
    {
        for (imp_patch_t *p_patch=ld_ptchs.p_ptchs;
            p_patch; p_patch=p_patch->next)
        {
            BOOL b_iat_pt=FALSE;
            /* IAT patches have sense only if the IAT table
               has been corrupted by ASPR */
            if (p_patch->proc_tpy==imp_key1_noiat ||
                p_patch->proc_tpy==imp_key2_noiat)
            {
                b_iat_pt=TRUE;
                ptiat_i++;
            }

            /* import patch */
            if (b_verb) dbgprintf("#%d: ", ++pt_i);
            if (apply_patch(p_patch->addr, p_patch->patch, p_patch->len, b_verb))
                pt_ok_i++;

            /* import's IAT patch */
            if (b_iat_pt && (flags&APLPTCHS_IAT_PATCH) && p_patch->len)
            {
                UINT8 iat_elem[4];
                iat_elem[0] = p_patch->proc_addr          & 0xff;
                iat_elem[1] = (p_patch->proc_addr >> 8)   & 0xff;
                iat_elem[2] = (p_patch->proc_addr >> 16)  & 0xff;
                iat_elem[3] = (p_patch->proc_addr >> 24)  & 0xff;

                if (b_verb) dbgprintf("; IAT patch: ");
                if (apply_patch(p_patch->iat_elem_addr,
                    iat_elem, sizeof(iat_elem), b_verb)) ptiat_ok_i++;
            }
            if (b_verb) dbgprintf("\n");

            /* emul patch */
            if (p_patch->p_emul) {
                if (b_verb) dbgprintf("#%d: ", ++pt_i);
                if (apply_patch(p_patch->p_emul->addr, p_patch->p_emul->patch,
                    p_patch->p_emul->len, b_verb))
                {
                    pt_ok_i++;
                }
                if (b_verb) dbgprintf("\n");
            }
        }

        info_dbgprintf("Applied %d/%d patches", pt_ok_i, pt_i);
        if (flags&APLPTCHS_IAT_PATCH) dbgprintf(" and %d/%d IAT table entries "
            "patches", ptiat_ok_i, ptiat_i);
        dbgprintf("\n");
    } else
        info_dbgprintf("No loaded patches\n");
}

/* Print loaded patches */
void print_patches()
{
    if (ld_ptchs.p_ptchs)
    {
        UINT i=0;
        char ptch_hex[100];

        for (imp_patch_t *p_patch=ld_ptchs.p_ptchs; p_patch;
            p_patch=p_patch->next)
        {
            i++;
            dbgprintf("%d. Import patch\n", i);

            dbgprintf("  Protection type: ");
            if (p_patch->type==ptch_sip)
                dbgprintf("Standard\n");
            else
            if (p_patch->type==ptch_esip)
                dbgprintf("Enhanced standard\n");
            else
            if (p_patch->p_emul)
                dbgprintf("Advanced with emulated opcode (see the next patch)\n");
            else
                dbgprintf("Advanced w/o emulated opcode\n");

            dbgprintf("  Import:          %s\n", p_patch->pc_desc);
            dbgprintf("  Reference type:  %s\n",
                (p_patch->ref_jmp ? "JMP" : "CALL"));
            dbgprintf("  Appl. address:   0x%p\n", p_patch->addr);

            dbgprintf("  Patch data:      ");
            if (p_patch->len) {
                bts2hex(p_patch->patch, p_patch->len, ptch_hex);
                dbgprintf("%s\n", ptch_hex);
            } else {
                dbgprintf("Can't resolve patch. Patch manually! Patch space: %d\n",
                    p_patch->sp_len);
            }

            if (p_patch->p_emul)
            {
                i++;
                dbgprintf("%d. Emulated opcode patch\n", i);
                dbgprintf("  Opcode:          %s\n", p_patch->p_emul->pc_desc);
                dbgprintf("  Appl. address:   0x%p\n", p_patch->p_emul->addr);

                dbgprintf("  Patch data:      ");
                if (p_patch->p_emul->len) {
                    bts2hex(
                        p_patch->p_emul->patch, p_patch->p_emul->len, ptch_hex);
                    dbgprintf("%s\n", ptch_hex);
                } else {
                    dbgprintf("Can't resolve patch. Patch manually! Patch "
                        "space: %d\n", p_patch->p_emul->sp_len);
                }
            }
        }
    } else info_dbgprintf("No loaded patches\n");
}

/* -------- PE file's handling procs -------- */

/* supported PE formats */
typedef enum _pe_header_type_t
{
    pe_32bit,
    pe_64bit
} pe_header_type_t;

typedef struct _image_nt_headers_t
{
    pe_header_type_t pe_tpy;

    union {
        IMAGE_NT_HEADERS32 pe32;    /* pe_32bit */
        IMAGE_NT_HEADERS64 pe64;    /* pe_64bit */
    } hdr;
} image_nt_headers_t;

/* Macros for accessing common PE32/PE32+ headers' components: 'Signature' and
   'FileHeader' */
#define get_Signature(h)  ((h)->hdr.pe32.Signature)
#define get_FileHeader(h) ((h)->hdr.pe32.FileHeader)


/* Read DOS & NT headers for a module with base 'mod_base'. Write them under
   'p_dos_hdr' & 'p_nt_hdrs'. If 'p_sectab_addr' is not NULL the address of the
   section table will be written under the pointer. If 'b_logs' is TRUE print
   error info. Returns TRUE for success.
 */
static BOOL read_pe_headers(ULONG64 mod_base, IMAGE_DOS_HEADER *p_dos_hdr,
    image_nt_headers_t *p_nt_hdrs, ULONG64 *p_sectab_addr, BOOL b_logs)
{
    ULONG cb;
    BOOL ret=FALSE;
    DWORD hdrs_off=0;

   /* read DOS header */
    if (!(read_memory(mod_base, p_dos_hdr, sizeof(*p_dos_hdr), &cb) &&
        cb==sizeof(*p_dos_hdr))) goto finish;
    if (p_dos_hdr->e_magic != IMAGE_DOS_SIGNATURE) {
        if (b_logs)
            err_dbgprintf("Invalid DOS header; magic: 0x%04X\n",
                (UINT)get_16uint_le(&p_dos_hdr->e_magic));
        goto finish;
    }

    /* read PE signature, PE header & optional header */
    hdrs_off = get_32uint_le(&p_dos_hdr->e_lfanew);
    ULONG64 nt_hdrs_addr = mod_base + hdrs_off;

    if (!(read_memory(
        nt_hdrs_addr, &(p_nt_hdrs->hdr), sizeof(p_nt_hdrs->hdr), &cb) &&
        cb==sizeof(p_nt_hdrs->hdr))) goto finish;
    if (get_Signature(p_nt_hdrs) != IMAGE_NT_SIGNATURE) {
        if (b_logs) {
            err_dbgprintf("Invalid PE header; signature 0x%08X\n",
                get_32uint_le(&get_Signature(p_nt_hdrs)));
        }
        goto finish;
    }

    DWORD opt_hdr_sz =
        get_16uint_le(&get_FileHeader(p_nt_hdrs).SizeOfOptionalHeader);
    hdrs_off += sizeof(get_Signature(p_nt_hdrs)) +
        sizeof(get_FileHeader(p_nt_hdrs)) + opt_hdr_sz;

    if (opt_hdr_sz<=0) {
        if (b_logs) err_dbgprintf("No optional header\n");
        goto finish;
    }

    /* check the opt header */
    WORD opt_magic = get_16uint_le(&p_nt_hdrs->hdr.pe32.OptionalHeader.Magic);
    if (opt_magic==IMAGE_NT_OPTIONAL_HDR32_MAGIC) p_nt_hdrs->pe_tpy=pe_32bit;
    else
    if (opt_magic==IMAGE_NT_OPTIONAL_HDR64_MAGIC)  p_nt_hdrs->pe_tpy=pe_64bit;
    else
    {
        if (b_logs)
            err_dbgprintf("Unsupported PE type: 0x%04X\n", (UINT)opt_magic);
        goto finish;
    }

    DWORD base_opt_hdr_len =
        (p_nt_hdrs->pe_tpy==pe_32bit ?
        ((UINT8*)&p_nt_hdrs->hdr.pe32.OptionalHeader.DataDirectory -
            (UINT8*)&p_nt_hdrs->hdr.pe32.OptionalHeader.Magic):
        ((UINT8*)&p_nt_hdrs->hdr.pe64.OptionalHeader.DataDirectory -
            (UINT8*)&p_nt_hdrs->hdr.pe64.OptionalHeader.Magic));

    if (base_opt_hdr_len >= opt_hdr_sz) {
        if (b_logs) err_dbgprintf("No NT specific optional header\n");
        goto finish;
    }

    if (p_sectab_addr) *p_sectab_addr = mod_base+hdrs_off;

    ret=TRUE;
finish:
    return ret;
}

/* Find a data directory entry 'dir_id' in the optional header and write its
   address under 'pp_dir_entry'. If 'b_logs' is TRUE print error info. Returns
   TRUE for success.
 */
static BOOL get_data_dir(const image_nt_headers_t *p_nt_hdrs,
    UINT dir_id, IMAGE_DATA_DIRECTORY **pp_dir_entry, BOOL b_logs)
{
    BOOL ret=FALSE;

    DWORD num_dir_ents =
        (p_nt_hdrs->pe_tpy==pe_32bit ?
        get_32uint_le(&p_nt_hdrs->hdr.pe32.OptionalHeader.NumberOfRvaAndSizes):
        get_32uint_le(&p_nt_hdrs->hdr.pe64.OptionalHeader.NumberOfRvaAndSizes));

    if (num_dir_ents <= dir_id) {
        if (b_logs) {
            err_dbgprintf("No PE dir entry for directory 0x%02X\n", dir_id);
        }
        goto finish;
    }

    *pp_dir_entry =
        (IMAGE_DATA_DIRECTORY*)(p_nt_hdrs->pe_tpy==pe_32bit ?
        &p_nt_hdrs->hdr.pe32.OptionalHeader.DataDirectory[dir_id]:
        &p_nt_hdrs->hdr.pe64.OptionalHeader.DataDirectory[dir_id]);

    ret=TRUE;
finish:
    return ret;
}

/* Read the export directory and write the data into the structure pointed by
   'p_ed'. The func requires p_ed->mod_base to be set to the base of the module
   whose export dir need to be read. If 'b_logs' is TRUE print error info.
   Returns TRUE for success, FALSE otherwise
 */
static BOOL get_mod_exp_dir(mod_exp_dir_t *p_ed, BOOL b_logs)
{
    BOOL ret=FALSE;

    IMAGE_DOS_HEADER dos_hdr;
    image_nt_headers_t nt_hdrs;

    if (!read_pe_headers(p_ed->mod_base, &dos_hdr, &nt_hdrs, NULL, b_logs))
        goto finish;

    IMAGE_DATA_DIRECTORY *p_dd_exp;
    if (!get_data_dir(&nt_hdrs, IMAGE_DIRECTORY_ENTRY_EXPORT, &p_dd_exp, b_logs))
        goto finish;

    ULONG64 exp_addr =
        RVA2ADDR(get_32uint_le(&p_dd_exp->VirtualAddress), p_ed->mod_base);

    ULONG cb;
    IMAGE_EXPORT_DIRECTORY exp_dir;

    if (!(read_memory(exp_addr, &exp_dir, sizeof(exp_dir), &cb) &&
        cb==sizeof(exp_dir))) goto finish;

    p_ed->ord_base = get_32uint_le(&exp_dir.Base);
    p_ed->n_faddrs = get_32uint_le(&exp_dir.NumberOfFunctions);
    p_ed->n_fnames = get_32uint_le(&exp_dir.NumberOfNames);
    p_ed->mod_name_addr = RVA2ADDR(
        get_32uint_le(&exp_dir.Name), p_ed->mod_base);
    p_ed->faddrs_addr = RVA2ADDR(
        get_32uint_le(&exp_dir.AddressOfFunctions), p_ed->mod_base);
    p_ed->fnames_addr = RVA2ADDR(
        get_32uint_le(&exp_dir.AddressOfNames), p_ed->mod_base);
    p_ed->fords_addr = RVA2ADDR(
        get_32uint_le(&exp_dir.AddressOfNameOrdinals), p_ed->mod_base);

    ret=TRUE;
finish:
    return ret;
}

/* Resolve module name and write its export dir under 'p_ed' */
BOOL reslv_mod(const char *pc_mod_name, mod_exp_dir_t *p_ed, BOOL b_logs)
{
    BOOL ret=FALSE;
    IDebugSymbols *DebugSymbols=NULL;

    if ((get_client()->QueryInterface(
        __uuidof(IDebugSymbols), (void **)&DebugSymbols)) != S_OK) goto finish;

    ULONG64 mod_base;
    if (DebugSymbols->GetModuleByModuleName(
        pc_mod_name, 0, NULL, &mod_base)!=S_OK)
    {
        if (b_logs)
            err_dbgprintf("Unable to find the module: %s\n", pc_mod_name);
        goto finish;
    }

    p_ed->mod_base = mod_base;
    if (!get_mod_exp_dir(p_ed, b_logs)) goto finish; 

    ret=TRUE;
finish:
    return ret;
}

/* Resolve proc name and write its addr under 'p_proc_addr'. Export directory
   retrieved by reslv_mod() is pointed by 'p_ed'. If proc_ord!=-1 then the
   ordinal is used for resolution, otherwise 'pc_proc_name' must point to proc
   name.
 */
BOOL reslv_import(
    const mod_exp_dir_t *p_ed, const char *pc_proc_name,
    UINT32 proc_ord, ULONG64 *p_proc_addr, BOOL b_logs)
{
    ULONG cb;
    BOOL ret=FALSE;

    *p_proc_addr = 0;

    if (proc_ord==(UINT32)-1)
    {
        if (p_ed->n_fnames<=0) goto finish;

        /* search for the proc name in the exported table of names;
           optimized method basing on lexical order of names in the table */
        DWORD hint=(DWORD)-1;
        BOOL loop_finish=FALSE;

        for (DWORD h_min=0, h_max=p_ed->n_fnames-1, h_mid; !loop_finish;)
        {
            if (h_min==h_max) loop_finish=TRUE;

            /* read proc name address in the middle of the searching range */
            h_mid = (h_min+h_max)/2;

            DWORD proc_name_rva;
            if (!(read_memory(p_ed->fnames_addr + h_mid*sizeof(proc_name_rva),
                &proc_name_rva, sizeof(proc_name_rva), &cb) &&
                cb==sizeof(proc_name_rva))) goto finish;

            ULONG64 proc_name_addr =
                RVA2ADDR(get_32uint_le(&proc_name_rva), p_ed->mod_base);

            int cmp_res = string_cmp_lt(pc_proc_name, proc_name_addr);
            if (!cmp_res) {
                hint = h_mid;
                break;
            } else
            if (cmp_res>0) {
                h_min = (h_min!=h_mid ? h_mid : h_max);
            } else {
                if (h_min!=h_mid) h_max=h_mid;
                else break;
            }
        }

        if (hint==(DWORD)-1) {
            if (b_logs)
                err_dbgprintf("Can not resolve proc name: %s\n", pc_proc_name);
            goto finish;
        }

        /* get position in EAT */
        WORD ord;
        if (!(read_memory(p_ed->fords_addr+hint*sizeof(ord),
            &ord, sizeof(ord), &cb) && cb==sizeof(ord))) goto finish;

        proc_ord = get_16uint_le(&ord);
    } else {
        /* convert ordinal to position in EAT */
        proc_ord = proc_ord-p_ed->ord_base;
    }

    /* read address from EAT */
    DWORD exp_proc_rva;
    if (!(read_memory(p_ed->faddrs_addr+proc_ord*sizeof(exp_proc_rva),
        &exp_proc_rva, sizeof(exp_proc_rva), &cb) && cb==sizeof(exp_proc_rva)))
        goto finish;
    *p_proc_addr = RVA2ADDR(get_32uint_le(&exp_proc_rva), p_ed->mod_base);

    ret=TRUE;
finish:
    return ret;
}

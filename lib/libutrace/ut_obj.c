/*
 * Copyright 2017 Dell Inc. or its subsidiaries.  All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <sys/types.h>
#include <sys/param.h>

#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <dlfcn.h>
#include <elf.h>

#include <nelf.h>
#include <utrace_impl.h>

static void
utrace_ehdr_to_shdr(const NElf_Ehdr *e, NElf_Shdr *s)
{
	s->sh_name = 0;
	s->sh_type = 0;
	s->sh_flags = 0;
	s->sh_addr = 0;
	s->sh_offset = e->e_shoff;
	s->sh_size = e->e_shentsize * e->e_shnum;
	s->sh_link = e->e_shstrndx;
	s->sh_info = 0;
	s->sh_addralign = 0;
	s->sh_entsize = e->e_shentsize;
}

static inline int
__attribute__((always_inline))
utrace_sym_skip(uint8_t type)
{
	return (type >= STT_NUM || type == STT_SECTION);
}

static int
__attribute__ ((optimize("omit-frame-pointer")))
utrace_sym_sort(NElf_Sym *l, NElf_Sym *r)
{
	const int mask = 1 << STT_OBJECT | 1 << STT_FUNC | 1 << STT_COMMON;
	const NElf_Word l_str = l->st_name;
	const NElf_Word r_str = r->st_name;
	const NElf_Addr l_addr = l->st_value;
	const NElf_Addr r_addr = r->st_value;
	const NElf_Word l_size = l->st_size;
	const NElf_Word r_size = r->st_size;
	const unsigned char l_typ = NELF_ST_TYPE(l->st_info);
	const unsigned char r_typ = NELF_ST_TYPE(r->st_info);
	const unsigned char l_bnd = NELF_ST_BIND(l->st_info);
	const unsigned char r_bnd = NELF_ST_BIND(r->st_info);

	if (l_addr != r_addr)
		return (l_addr > r_addr ? 1 : -1);

	if (l_size != 0 && r_size == 0)
		return (-1);

	if (l_size == 0 && r_size != 0)
		return (+1);

	if ((1 << l_typ & mask) != 0 && (1 << r_typ & mask) == 0)
		return (-1);

	if ((1 << l_typ & mask) == 0 && (1 << r_typ & mask) != 0)
		return (+1);

	if (l_bnd != STB_WEAK && r_bnd == STB_WEAK)
		return (-1);

	if (l_bnd == STB_WEAK && r_bnd != STB_WEAK)
		return (+1);

	if (l_str != r_str)
		return (l_str > r_str ? 1 : -1);

	return (0);
}

static void
utrace_sym_edit(NElf_Sym *symtab, size_t symlen)
{
	for (NElf_Sym *s = symtab; s < symtab + symlen; s++) {
		if (s->st_value != 0 &&
		    utrace_sym_skip(NELF_ST_TYPE(s->st_info)))
			s->st_value = 0; /* force sym out of search path */

		if (s->st_size != 0 && NELF_ST_TYPE(s->st_info) == STT_TLS)
			s->st_size = 0; /* force tls out of search path */
	}
}

static int
__attribute__ ((optimize("omit-frame-pointer")))
utrace_sym_find(const NElf_Sym *k, const NElf_Sym *s)
{
	if (k->st_value - s->st_value < MAX(s->st_size, 1))
		return (0); /* key in range [st_value, st_value + st_size) */

	return (k->st_value > s->st_value ? 1 : -1);
}

void
utrace_obj_init(ut_obj_t *obj)
{
	bzero(obj, sizeof (*obj));
	(void) pthread_mutex_init(&obj->utob_prlock, NULL);
}

int
utrace_obj_load(utrace_handle_t *uhp, ut_obj_t *obj, const char *file)
{
	utrace_probe_t *p;
	int fd, err = 0;

	NElf_Ehdr ehdr;

	NElf_Shdr hdr, str, prb_sec, sym_sec, str_sec;
	size_t hdr_ent, hdr_len, str_len;
	uint8_t *hdr_buf, *str_buf;

	if ((fd = open(file, O_RDONLY)) == -1)
		return (utrace_error(uhp, errno, "failed to open %s", file));

	bzero(&hdr, sizeof (hdr));

	if (read(fd, &ehdr, sizeof (ehdr)) != sizeof (ehdr))
		err = utrace_error(uhp, errno, "failed to read ELF header");
	else if (ehdr.e_ident[EI_CLASS] != NELFCLASS)
		err = utrace_error(uhp, EINVAL, "ELF class mismatch");
	else if (ehdr.e_ident[EI_DATA] != NELFDATA)
		err = utrace_error(uhp, EINVAL, "ELF endian mismatch");
	else if (ehdr.e_type != ET_EXEC)
		err = utrace_error(uhp, EINVAL, "ELF type is not executable");
	else
		utrace_ehdr_to_shdr(&ehdr, &hdr);

	if (hdr.sh_size > 0 && hdr.sh_entsize == 0)
		err |= utrace_error(uhp, EINVAL, "invalid ELF header");

	if (err != 0)
		goto out;

	hdr_ent = hdr.sh_entsize;
	hdr_len = hdr.sh_size;
	hdr_buf = vmem_zalloc(vmem_heap, hdr_len, VM_SLEEP);

	if (pread(fd, hdr_buf, hdr_len, hdr.sh_offset) != (ssize_t)hdr_len)
		err |= utrace_error(uhp, errno, "failed to read shdrs");

	bcopy(hdr_buf + hdr.sh_link * hdr_ent,
	    &str, MIN(hdr_ent, sizeof (str)));

	str_len = str.sh_size + 1;
	str_buf = vmem_zalloc(vmem_heap, str_len, VM_SLEEP);

	if (pread(fd, str_buf, str_len, str.sh_offset) != (ssize_t)str_len)
		err |= utrace_error(uhp, errno, "failed to read .shstrtab");

	bzero(&prb_sec, sizeof (prb_sec));
	bzero(&sym_sec, sizeof (sym_sec));
	bzero(&str_sec, sizeof (str_sec));

	/*
	 * Iterate over the section headers, copying out the headers for
	 * utrace probes, the primary symbol table, and its string table.
	 */
	for (uint8_t *s = hdr_buf; s < hdr_buf + hdr_len; s += hdr_ent) {
		bcopy(s, &hdr, MIN(hdr_ent, sizeof (hdr)));

		if (hdr.sh_name >= str_len)
			continue; /* skip anything w/ corrupt sh_name */

		if (strcmp((char *)str_buf + hdr.sh_name, ".utrace") == 0)
			bcopy(&hdr, &prb_sec, sizeof (prb_sec));
		else if (hdr.sh_type == SHT_SYMTAB)
			bcopy(&hdr, &sym_sec, sizeof (sym_sec));
		else if (hdr.sh_type == SHT_STRTAB)
			bcopy(&hdr, &str_sec, sizeof (str_sec));
	}

	if (sym_sec.sh_size > 0 && sym_sec.sh_entsize == 0)
		err |= utrace_error(uhp, EINVAL, "invalid .symtab header");

	obj->utob_probev = vmem_alloc(vmem_heap, prb_sec.sh_size, VM_SLEEP);
	obj->utob_probec = prb_sec.sh_size / sizeof (utrace_probe_t);

	if (pread(fd, obj->utob_probev, prb_sec.sh_size,
	    prb_sec.sh_offset) != (ssize_t)prb_sec.sh_size)
		err |= utrace_error(uhp, errno, "failed to read .utrace");

	for (p = obj->utob_probev; p < obj->utob_probev + obj->utob_probec; p++)
		p->prb_prid = (uint32_t)(p - obj->utob_probev);

	obj->utob_symtab = vmem_alloc(vmem_heap, sym_sec.sh_size, VM_SLEEP);
	obj->utob_symlen = sym_sec.sh_size;
	obj->utob_syment = sym_sec.sh_entsize;

	if (pread(fd, obj->utob_symtab, obj->utob_symlen,
	    sym_sec.sh_offset) != (ssize_t)sym_sec.sh_size)
		err |= utrace_error(uhp, errno, "failed to read .symtab");

	obj->utob_strtab = vmem_alloc(vmem_heap, str_sec.sh_size + 1,
	    VM_SLEEP);
	obj->utob_strtab[str_sec.sh_size] = '\0';
	obj->utob_strlen = str_sec.sh_size + 1;

	if (pread(fd, obj->utob_strtab, str_sec.sh_size,
	    str_sec.sh_offset) != (ssize_t)str_sec.sh_size)
		err |= utrace_error(uhp, errno, "failed to read .strtab");

	if (err == 0 && obj->utob_symlen > 0) {
		utrace_sym_edit(obj->utob_symtab,
		    obj->utob_symlen / obj->utob_syment);
		qsort(obj->utob_symtab, obj->utob_symlen / obj->utob_syment,
		    obj->utob_syment, (__compar_fn_t)utrace_sym_sort);
	}

	vmem_free(vmem_heap, str_buf, str_len);
	vmem_free(vmem_heap, hdr_buf, hdr_len);
out:
	(void) close(fd);
	return (err);
}

void
utrace_obj_free(ut_obj_t *obj)
{
	vmem_free(vmem_heap, obj->utob_probev,
	    obj->utob_probec * sizeof (utrace_probe_t));

	vmem_free(vmem_heap, obj->utob_symtab, obj->utob_symlen);
	vmem_free(vmem_heap, obj->utob_strtab, obj->utob_strlen);
}

void
utrace_obj_hold(ut_obj_t *obj)
{
	__sync_add_and_fetch(&obj->utob_refs, 1);
}

void
utrace_obj_rele(ut_obj_t *obj)
{
	if (__sync_sub_and_fetch(&obj->utob_refs, 1) == 0)
		utrace_obj_free(obj);
}

size_t
utrace_obj_name(ut_obj_t *obj, uintptr_t val, char *buf, size_t len)
{
	const char *sym = NULL;
	size_t rlen, off = 0;
	Dl_info dli;

	NElf_Sym k, *p, *q;
	k.st_value = val;
	k.st_size = 1;

	if (val == 0)
		return (snprintf(buf, len, "0x0"));

	if (obj->utob_symlen > 0) {
		q = p = bsearch(&k, obj->utob_symtab,
		    obj->utob_symlen / obj->utob_syment, obj->utob_syment,
		    (__compar_fn_t)utrace_sym_find);

		while (q-- > (NElf_Sym *)obj->utob_symtab &&
		    q->st_value == p->st_value)
			p = q;

		if (p != NULL) {
			sym = obj->utob_strtab + p->st_name;
			off = val - p->st_value;
		}
	}

	/*
	 * Now format the output symbol name as sym or sym+off.  If we do not
	 * find a match in .symtab, but we're examining the current executable,
	 * try to use libdl to find a matching symbol in another load object.
	 */
	if (sym != NULL && off == 0)
		rlen = snprintf(buf, len, "%s", sym);
	else if (sym != NULL && off != 0)
		rlen = snprintf(buf, len, "%s+0x%zx", sym, off);
	else if (obj != &UT_exec ||
	    dladdr((void *)val, &dli) == 0 || dli.dli_sname == NULL)
		rlen = snprintf(buf, len, "0x%tx", (uintptr_t)val);
	else if (dli.dli_saddr == (void *)val)
		rlen = snprintf(buf, len, "%s`%s",
		    basename(dli.dli_fname), dli.dli_sname);
	else
		rlen = snprintf(buf, len, "%s`%s+0x%tx",
		    basename(dli.dli_fname), dli.dli_sname,
		    (void *)val - dli.dli_saddr);

	return (rlen);
}

size_t
utrace_symbol(utrace_handle_t *uhp, uintptr_t val, char *buf, size_t len)
{
	return (utrace_obj_name(uhp->uth_obj, val, buf, len));
}

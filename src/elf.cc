
/* Copyright 2015 Bloq Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <string>
#include <vector>
#include <libelf.h>
#include <gelf.h>
#include <stdio.h>
#include "moxievm.h"

#ifndef EM_MOXIE
#define EM_MOXIE                223  /* Official Moxie */
#endif // EM_MOXIE

#ifndef EM_MOXIE_OLD
#define EM_MOXIE_OLD            0xFEED /* Old Moxie */
#endif // EM_MOXIE_OLD

using namespace std;

bool machine::loadElfProgSection(Elf *e, GElf_Phdr *phdr, void *p)
{
	bool writable = (phdr->p_flags & PF_W);
	size_t sz = phdr->p_memsz;
	static unsigned int elfCount = 0;
	char tmpstr[32];

	sprintf(tmpstr, "elf%u", elfCount++);
	addressRange *rdr = new addressRange(tmpstr, sz);

	rdr->start = phdr->p_vaddr;
	rdr->length = sz;
	rdr->end = rdr->start + rdr->length;
	rdr->readOnly = (writable ? false : true);

	char *cp = (char *) p;
	rdr->buf.assign(cp + phdr->p_offset, phdr->p_filesz);
	rdr->buf.resize(phdr->p_memsz);
	rdr->updateRoot();

	memmap.push_back(rdr);
	sortMemMap();

	return true;
}

bool machine::loadElfBuffer(char *pf_data, size_t pf_size)
{
	if ( elf_version ( EV_CURRENT ) == EV_NONE )
		return false;

	Elf *e;
	if (( e = elf_memory(pf_data, pf_size)) == NULL )
		return false;

	if ( elf_kind ( e ) != ELF_K_ELF )
		goto err_out_elf;

	GElf_Ehdr ehdr;
	if (gelf_getehdr(e, &ehdr) != &ehdr)
		goto err_out_elf;

	if ((ehdr.e_ident[EI_CLASS] != ELFCLASS32) ||
	    (ehdr.e_ident[EI_DATA] != ELFDATA2LSB) ||
	    ((ehdr.e_machine != EM_MOXIE)
	     && (ehdr.e_machine != EM_MOXIE_OLD))) {
		goto err_out_elf;
	}

	startAddr = ehdr.e_entry;

	size_t n;
	if ( elf_getphdrnum (e , & n ) != 0)
		goto err_out_elf;

	unsigned int i;
	GElf_Phdr phdr;
	for (i = 0; i < n; i++) {
		if ( gelf_getphdr (e, i, &phdr) != &phdr )
			goto err_out_elf;

		if (phdr.p_type != PT_LOAD) {
			continue;
		}

		if (!loadElfProgSection(e, &phdr, pf_data))
			goto err_out_elf;
	}

	elf_end(e);
	return true;

err_out_elf:
	elf_end(e);
	return false;
}


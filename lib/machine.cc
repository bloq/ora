
/* Copyright 2015 Bloq Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <algorithm>
#include <vector>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "moxievm.h"

using namespace std;

namespace Moxie {

void *machine::physaddr(uint32_t addr, size_t objLen, bool wantWrite)
{
	for (unsigned int i = 0; i < memmap.size(); i++) {
		addressRange* mr = memmap[i];
		if (mr->inRange(addr, objLen)) {
			if (wantWrite && mr->readOnly)
				return NULL;
			return mr->physaddr(addr);
		}
	}

	return NULL;
}

bool machine::read8(uint32_t addr, uint32_t& val_out)
{
	uint8_t *paddr = (uint8_t *) physaddr(addr, 1);
	if (!paddr)
		return false;

	val_out = *paddr;
	return true;
}

bool machine::read16(uint32_t addr, uint32_t& val_out)
{
	uint16_t *paddr = (uint16_t *) physaddr(addr, 2);
	if (!paddr)
		return false;

	val_out = *paddr;
	return true;
}

bool machine::read32(uint32_t addr, uint32_t& val_out)
{
	uint32_t *paddr = (uint32_t *) physaddr(addr, 4);
	if (!paddr)
		return false;

	val_out = *paddr;
	return true;
}

bool machine::write8(uint32_t addr, uint32_t val)
{
	uint8_t *paddr = (uint8_t *) physaddr(addr, 1, true);
	if (!paddr)
		return false;

	*paddr = (uint8_t) val;
	return true;
}

bool machine::write16(uint32_t addr, uint32_t val)
{
	uint16_t *paddr = (uint16_t *) physaddr(addr, 2, true);
	if (!paddr)
		return false;

	*paddr = (uint16_t) val;
	return true;
}

bool machine::write32(uint32_t addr, uint32_t val)
{
	uint32_t *paddr = (uint32_t *) physaddr(addr, 4, true);
	if (!paddr)
		return false;

	*paddr = val;
	return true;
}

static bool memmapCmp(addressRange *a, addressRange *b)
{
	return (a->start < b->start);
}

void machine::sortMemMap()
{
	std::sort(memmap.begin(), memmap.end(), memmapCmp);
}

bool machine::mapInsert(addressRange *rdr)
{
	addressRange *ar = memmap.back();
	rdr->start = ar->end + MACH_PAGE_SIZE;
	rdr->end = rdr->start + rdr->length;
	memmap.push_back(rdr);

	return true;
}

void machine::fillDescriptors(std::vector<struct mach_memmap_ent>& desc)
{
	for (unsigned int i = 0; i < memmap.size(); i++) {
		addressRange* ar = memmap[i];

		struct mach_memmap_ent mme;
		mme.vaddr = ar->start;
		mme.length = ar->length;
		memset(&mme.tags, 0, sizeof(mme.tags));
		strcpy(mme.tags, ar->readOnly ? "ro," : "rw,");
		strcat(mme.tags, ar->name.c_str());
		strcat(mme.tags, ",");

		desc.push_back(mme);
	}
}

static const size_t SECTION_NAME_MAX = 32 - 1;

static bool validSectionName(const std::string& name)
{
	if (name.empty())
		return false;
	if (name.size() > SECTION_NAME_MAX)
		return false;
	for (size_t i = 0; i < name.size(); i++)
		if (!isalnum(name[i]))
			return false;
	return true;
}

bool machine::loadRawData(unsigned int& dataCount, const void *data,
			  size_t data_len, const std::string& sectionName)
{
	char tmpstr[SECTION_NAME_MAX + 1];

	if (sectionName.empty())
		sprintf(tmpstr, "data%u", dataCount);
	else if (validSectionName(sectionName))
		strcpy(tmpstr, sectionName.c_str());
	else
		return false;
	dataCount++;

	// alloc new data memory range
	addressRange *rdr = new addressRange(tmpstr, data_len);

	// copy mmap'd data into local buffer
	rdr->buf.assign((char *)data, data_len);
	rdr->updateRoot();

	// add to global memory map
	return mapInsert(rdr);
}

void machine::addStackMem()
{
	// alloc r/w memory range
	addressRange *rdr = new addressRange("stack", MACH_STACK_SIZE);

	rdr->buf.resize(MACH_STACK_SIZE);
	rdr->updateRoot();
	rdr->readOnly = false;

	// add memory range to global memory map
	mapInsert(rdr);

	// set SR #7 to now-initialized stack vaddr
	cpu.asregs.sregs[7] = rdr->end;
}

void machine::addMapDescriptor()
{
	// fill list from existing memory map
	vector<struct mach_memmap_ent> desc;
	fillDescriptors(desc);

	// add entry for the mapdesc range to be added to memory map
	struct mach_memmap_ent mme_self;
	memset(&mme_self, 0, sizeof(mme_self));
	desc.push_back(mme_self);

	// add blank entry for list terminator
	struct mach_memmap_ent mme_end;
	memset(&mme_end, 0, sizeof(mme_end));
	desc.push_back(mme_end);

	// calc total region size
	size_t sz = sizeof(mme_end) * desc.size();

	// manually fill in mapdesc range descriptor
	mme_self.length = sz;
	strcpy(mme_self.tags, "ro,mapdesc,");

	// build entry for global memory map
	addressRange *ar = new addressRange("mapdesc", sz);

	// allocate space for descriptor array
	ar->buf.resize(sz);
	ar->updateRoot();

	// copy 'desc' array into allocated memory space
	unsigned int i = 0;
	for (vector<struct mach_memmap_ent>::iterator it = desc.begin();
	     it != desc.end(); it++, i++) {
		struct mach_memmap_ent& mme = (*it);
		memcpy(&ar->buf[i * sizeof(mme)], &mme, sizeof(mme));
	}

	// add memory range to global memory map
	mapInsert(ar);

	// set SR #6 to now-initialized mapdesc start vaddr
	cpu.asregs.sregs[6] = ar->start;
}

void machine::finalizeInput()
{
	addStackMem();
	addMapDescriptor();

	cpu.asregs.regs[PC_REGNO] = startAddr;
}

} // namespace Moxie

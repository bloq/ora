#ifndef __MOXIEVM_H__
#define __MOXIEVM_H__

#include <cstdint>
#include <unordered_map>
#include <string>
#include <vector>
#include <string.h>
#include <libelf.h>
#include <gelf.h>
#include "moxie.h"

typedef std::unordered_map<uint32_t, uint32_t> gprof_bb_map_t;
typedef std::unordered_map<uint64_t, uint32_t> gprof_cg_map_t;

namespace Moxie {

enum {
	MACH_PAGE_SIZE = 4096,
	MACH_PAGE_MASK = (MACH_PAGE_SIZE-1),
};

struct mach_memmap_ent {
	uint32_t vaddr;
	uint32_t length;
	char tags[32 - 4 - 4];
};

class cpuState {
public:
	struct moxie_regset asregs;

	cpuState() {
		memset(&asregs, 0, sizeof(asregs));
	}
};

class addressRange {
public:
	std::string name;
	uint32_t start;
	uint32_t end;
	uint32_t length;
	void *root;
	bool readOnly;
	std::string buf;

	addressRange(std::string name_, size_t sz) {
		name = name_;
		start = 0;
		end = 0;
		length = sz;
		root = NULL;
		readOnly = true;
	}

	void *physaddr(uint32_t addr) {
		uint32_t offset = addr - start;
		return (char *)root + offset;
	}

	bool inRange(uint32_t addr, uint32_t len) {
		return ((addr >= start) &&
			((addr + len) <= end));		// warn: overflow
	}

	void updateRoot() { root = &buf[0]; }
};

class machine {
public:
	std::vector<addressRange*> memmap;
	cpuState cpu;

	uint32_t startAddr;
	bool tracing;
	bool profiling;
	uint32_t heapAvail;

	gprof_bb_map_t gprof_bb_data;
	gprof_cg_map_t gprof_cg_data;

	machine() {
		startAddr = 0;
		tracing = false;
		profiling = false;
		heapAvail = 0xfffffffU;
	}

	bool read8(uint32_t addr, uint32_t& val_out);
	bool read16(uint32_t addr, uint32_t& val_out);
	bool read32(uint32_t addr, uint32_t& val_out);

	bool write8(uint32_t addr, uint32_t val);
	bool write16(uint32_t addr, uint32_t val);
	bool write32(uint32_t addr, uint32_t val);

	void *physaddr(uint32_t addr, size_t objLen, bool wantWrite = false);
	void sortMemMap();
	bool mapInsert(addressRange *ar);
	void fillDescriptors(std::vector<struct mach_memmap_ent>& desc);

	bool loadElfBuffer(char *pf_data, size_t pf_size);
	bool loadRawData(unsigned int& dataCount, const void *data,
			 size_t data_len, const std::string& sectionName = "");
	bool loadRawData(unsigned int& dataCount, const std::string& data,
			 const std::string& sectionName = "") {
		if (data.empty())
			return false;
		return loadRawData(dataCount, &data[0], data.size(),
				   sectionName);
	}

private:
	bool loadElfProgSection(Elf *e, GElf_Phdr *phdr, void *p);
};

extern void sim_resume (machine& mach, unsigned long long cpu_budget = 0);

} // namespace Moxie

#endif // __MOXIEVM_H__

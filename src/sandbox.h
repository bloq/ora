#ifndef __SANDBOX_H__
#define __SANDBOX_H__

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#include <string>
#include <string.h>
#include <stdint.h>
#include <openssl/sha.h>
#include "moxievm.h"

static inline bool eqVec(const std::vector<unsigned char>& a,
			 const std::vector<unsigned char>& b)
{
	if (a.size() != b.size())
		return false;

	return (memcmp(&a[0], &b[0], a.size()) == 0);
}

class sha256hash {
private:
	SHA256_CTX ctx;

public:
	sha256hash(const void *p = NULL, size_t len = 0) {
		clear();
		if (p && len)
			update(p, len);
	}

	void clear() { SHA256_Init(&ctx); }
	void update(const void *p, size_t len) { SHA256_Update(&ctx, p, len); }
	void final(std::vector<unsigned char>& digest) {
		digest.resize(SHA256_DIGEST_LENGTH);
		SHA256_Final(&digest[0], &ctx);
	}
};

class mfile {
public:
	int fd;
	void *data;
	struct stat st;
	std::string pathname;

	mfile(const std::string& pathname_ = "") {
		fd = -1;
		data = NULL;
		pathname = pathname_;
	}
	~mfile() {
		if (data)
			munmap(data, st.st_size);
		if (fd >= 0)
			close(fd);
	}

	bool open(int flags, mode_t mode = 0, bool map = true);
};

extern bool loadElfBuffer(machine& mach, char *pf_data, size_t pf_size);
extern bool loadElfProgram(machine& mach, const std::string& filename);
extern bool loadElfHash(machine& mach, const std::string& hash,
			const std::vector<std::string>& pathExec);

extern signed char HexDigit(char c);
extern bool IsHex(const std::string& str);
extern std::vector<unsigned char> ParseHex(const char* psz);
extern std::vector<unsigned char> ParseHex(const std::string& str);
extern bool ReadDir(const std::string& pathname,
		    std::vector<std::string>& dirNames);
extern int write_pid_file(const char *pid_fn);

template<typename T>
std::string HexStr(const T itbegin, const T itend, bool fSpaces=false)
{
    std::string rv;
    static const char hexmap[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                                     '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    rv.reserve((itend-itbegin)*3);
    for(T it = itbegin; it < itend; ++it)
    {
        unsigned char val = (unsigned char)(*it);
        if(fSpaces && it != itbegin)
            rv.push_back(' ');
        rv.push_back(hexmap[val>>4]);
        rv.push_back(hexmap[val&15]);
    }

    return rv;
}

template<typename T>
inline std::string HexStr(const T& vch, bool fSpaces=false)
{
    return HexStr(vch.begin(), vch.end(), fSpaces);
}

#endif // __SANDBOX_H__

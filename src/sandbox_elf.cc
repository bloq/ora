
/* Copyright 2015 Bloq Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <string>
#include <vector>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <libelf.h>
#include <gelf.h>
#include <sys/mman.h>
#include <stdio.h>
#include "sandbox.h"

#ifndef EM_MOXIE
#define EM_MOXIE                223  /* Official Moxie */
#endif // EM_MOXIE

#ifndef EM_MOXIE_OLD
#define EM_MOXIE_OLD            0xFEED /* Old Moxie */
#endif // EM_MOXIE_OLD

using namespace std;

static bool loadElfFile(machine& mach, mfile& pf)
{
	return mach.loadElfBuffer((char *)pf.data, pf.st.st_size);
}

bool loadElfProgram(machine& mach, const string& filename)
{
	mfile pf(filename);
	if (!pf.open(O_RDONLY))
		return false;

	return loadElfFile(mach, pf);
}

bool loadElfHash(machine& mach, const string& hash,
		 const std::vector<std::string>& pathExec)
{
	vector<unsigned char> digest = ParseHex(hash);

	for (unsigned int i = 0; i < pathExec.size(); i++) {
		const std::string& path = pathExec[i];

		vector<string> dirNames;
		if (!ReadDir(path, dirNames)) {
			perror(path.c_str());
			continue;
		}

		for (vector<string>::iterator it = dirNames.begin();
		     it != dirNames.end(); it++) {
			string filename = path + "/" + (*it);

			mfile pf(filename);
			if (!pf.open(O_RDONLY)) {
				perror(filename.c_str());
				continue;
			}

			sha256hash hash(pf.data, pf.st.st_size);

			vector<unsigned char> tmpHash;
			hash.final(tmpHash);

			if (eqVec(digest, tmpHash))
				return loadElfFile(mach, pf);
		}
	}

	return false;
}


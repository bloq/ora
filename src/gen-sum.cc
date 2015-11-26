
/* Copyright 2015 Bloq Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <vector>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include "sandbox.h"

using namespace std;

static int hashFile(const char *filename)
{
	mfile pf(filename);
	if (!pf.open(O_RDONLY)) {
		perror(filename);
		return 1;
	}

	sha256hash hash(pf.data, pf.st.st_size);

	vector<unsigned char> digest;
	hash.final(digest);

	if (fwrite(&digest[0], 1, digest.size(), stdout) != digest.size()) {
		perror(filename);
		return 1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s FILE > SHA256-HASH.OUT\n", argv[0]);
		return 1;
	}

	return hashFile(argv[1]);
}


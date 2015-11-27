
/* Copyright 2015 Bloq Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include "ora-config.h"

#include <string>
#include <argp.h>
#include <unistd.h>

#include "oraapi.h"

using namespace std;

enum command_type {
	CMD_NONE,
	CMD_EXEC_INPUT,
};

static enum command_type opt_command = CMD_NONE;


/* Command line arguments and processing */
const char *argp_program_version =
	"pbmaker " VERSION "\n"
	"Copyright 2015 Bloq, Inc.\n"
	"This is free software; see the source for copying conditions.  There is NO "
	"warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.";

const char *argp_program_bug_address = PACKAGE_BUGREPORT;

static char doc[] =
	"Protocol buffers data structure generator\n";

static struct argp_option options[] = {
	{ "exec-input", 1001, NULL, 0,
	  "Generate ExecInput" },

	{ 0 },
};

/*
 * command line processing
 */
static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	switch(key) {
	case 1001:
		opt_command = CMD_EXEC_INPUT;
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static struct argp argp = { options, parse_opt, NULL, doc };

int main(int argc, char *argv[])
{
	/* Parsing of commandline parameters */
	argp_parse(&argp, argc, argv, 0, NULL, NULL);

	switch (opt_command) {
	case CMD_EXEC_INPUT: {
		Ora::ExecInput oreq;

		oreq.set_chain_id(Ora::ExecInput_ChainId_BITCOIN);

		assert(oreq.IsInitialized() == true);

		string s;
		bool rc = oreq.SerializeToString(&s);
		assert(rc == true);

		ssize_t wrc = write(STDOUT_FILENO, &s[0], s.size());
		assert(wrc == (ssize_t)s.size());
		break;
	}

	case CMD_NONE:
		break;
	}

	return 0;
}


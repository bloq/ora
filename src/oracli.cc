
/* Copyright 2015 Bloq Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

// Get rid of OSX 10.7 and greater deprecation warnings.
#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif
#include "ora-config.h"

#include <stdio.h>
#include <memory>
#include <string>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <argp.h>

#include <event2/event.h>

#include "oraapi.h"

#define DEFAULT_ENDPOINT "http://127.0.0.1:12014/"

using namespace std;

static struct event_base *base;
static std::string opt_url = DEFAULT_ENDPOINT;
static bool found_command = false;

enum command_type {
	CMD_INFO,
	CMD_EXEC,
};

enum http_scheme_type {
	HTTP,
	HTTPS
};

static enum command_type opt_command = CMD_INFO;

/* Command line arguments and processing */
const char *argp_program_version =
	"oracli " PACKAGE_VERSION "\n"
	"Copyright 2015 Bloq, Inc.\n"
	"This is free software; see the source for copying conditions.  There is NO "
	"warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.";

const char *argp_program_bug_address = PACKAGE_BUGREPORT;

static const char args_doc[] = "COMMAND [COMMAND-OPTIONS...]";

static char global_doc[] =
	"Client to Blockchain oracles\n"
	"\n"
	"Supported commands:\n"
	"  (empty) - Get endpoint metadata\n"
	"  exec - Execute Moxie program\n"
	"\n";

static struct argp_option options[] = {
	{ "url", 1001, "URL", 0,
	  "Target endpoint API URL (default: " DEFAULT_ENDPOINT ")" },

	{ 0 }
};

/*
 * command line processing
 */

static struct argp_option exec_options[] = {
	{ 0 }
};

static char exec_doc[] =
	"Execute a moxie program\n";

static error_t parse_exec_opt (int key, char *arg, struct argp_state *state)
{
	switch(key) {
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static struct argp argp_exec = { exec_options, parse_exec_opt, NULL, exec_doc };

static void parse_cmd_exec(struct argp_state* state)
{
	int    argc = state->argc - state->next + 1;
	char** argv = &state->argv[state->next - 1];
	char*  argv0 =  argv[0];

	string new_arg0(state->name);
	new_arg0.append(" exec");

	argv[0] = (char *) new_arg0.c_str();

	argp_parse(&argp_exec, argc, argv, ARGP_IN_ORDER, &argc, NULL);

	argv[0] = argv0;

	state->next += argc - 1;
}

static error_t parse_global_opt (int key, char *arg, struct argp_state *state)
{
	switch(key) {
	case 1001:
		opt_url = arg;
		break;

	case ARGP_KEY_ARG:
		found_command = true;
		if (strcmp(arg, "exec") == 0) {
			opt_command = CMD_EXEC;
			parse_cmd_exec(state);
		} else {
			argp_error(state, "%s is not a valid command", arg);
		}
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static struct argp argp = { options, parse_global_opt, args_doc, global_doc };

int
main(int argc, char **argv)
{
	/* Parsing of commandline parameters */
	argp_parse(&argp, argc, argv, ARGP_IN_ORDER, NULL, NULL);

	if (opt_url.empty())
		return 1;

	Ora::init_library();

	// Create event base
	base = event_base_new();
	if (!base) {
		perror("event_base_new()");
		return 1;
	}

	// Create client instance
	Ora::Client oc(base);

	if (!oc.open(opt_url)) {
		fprintf(stderr, "Client.open failed for %s\n", opt_url.c_str());
		return 1;
	}

	// make RPC call
	switch (opt_command) {
	case CMD_INFO: {
		UniValue meta;
		if (!oc.info(meta)) {
			fprintf(stderr, "Client.info failed for %s\n", opt_url.c_str());
			return 1;
		}

		printf("%s\n", meta.write(2).c_str());
		break;
	}

	case CMD_EXEC: {
		Ora::ExecInput ei;
		ei.set_chain_id(Ora::ExecInput_ChainId_BITCOIN);
		assert(ei.IsInitialized() == true);

		Ora::ExecOutput eo;
		if (!oc.exec(ei, eo)) {
			fprintf(stderr, "Client.exec failed for %s\n", opt_url.c_str());
			return 1;
		}

		printf("EXEC successful\n");
		break;
	}
	}

	return 0;
}

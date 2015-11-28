
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <event2/event.h>
#include <univalue.h>

#include "sandbox.h"
#include "oraapi.h"

using namespace std;

#define DEFAULT_ENDPOINT "http://127.0.0.1:12014/"

static struct event_base *base;
static string opt_url(DEFAULT_ENDPOINT);
static string top_srcdir;

static void test_info(Ora::Client& oc)
{
	UniValue meta;
	bool rc = oc.info(meta);
	assert(rc == true);
}

static uint32_t test_simple_exec(Ora::Client& oc, const string& filename)
{
	bool rc;

	mfile pf(filename);
	rc = pf.open(O_RDONLY);
	assert(rc == true);

	Ora::ExecInput ei;
	ei.set_want_output(false);
	ei.set_chain_id(Ora::ExecInput_ChainId_BITCOIN);
	execInputAdd(ei, pf.data, pf.st.st_size);

	assert(ei.IsInitialized() == true);

	Ora::ExecOutput eo;
	rc = oc.exec(ei, eo);
	assert(rc == true);

	return eo.return_code();
}

int main (int argc, char *argv[])
{
	top_srcdir.assign(getenv("TOP_SRCDIR"));

	Ora::init_library();

	// Create event base
	base = event_base_new();
	assert(base != NULL);

	// Create client instance
	Ora::Client oc(base);

	bool rc = oc.open(opt_url);
	assert(rc == true);

	test_info(oc);

	uint32_t rc32;
	rc32 = test_simple_exec(oc, "exit0");
	assert(rc32 == 0);

	rc32 = test_simple_exec(oc, "exit1");
	assert(rc32 == 1);

	rc32 = test_simple_exec(oc, "basic");
	assert(rc32 == 0);

	return 0;
}


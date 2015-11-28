
#include <string>
#include <stdio.h>
#include <event2/event.h>
#include <univalue.h>

#include "oraapi.h"

using namespace std;

#define DEFAULT_ENDPOINT "http://127.0.0.1:12014/"

static struct event_base *base;
static string opt_url(DEFAULT_ENDPOINT);

static void test_info(Ora::Client& oc)
{
	UniValue meta;
	bool rc = oc.info(meta);
	assert(rc == true);
}

int main (int argc, char *argv[])
{
	Ora::init_library();

	// Create event base
	base = event_base_new();
	assert(base != NULL);

	// Create client instance
	Ora::Client oc(base);

	bool rc = oc.open(opt_url);
	assert(rc == true);

	test_info(oc);

	return 0;
}


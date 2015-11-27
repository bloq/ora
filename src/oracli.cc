
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
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <argp.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include <event2/bufferevent_ssl.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/http.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

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

static void cmd_info_response(const string& http_body);
static void cmd_exec_response(const string& http_body);

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

static void cmd_stdout_response(const string& http_body)
{
	ssize_t wrc = write(STDOUT_FILENO, &http_body[0], http_body.size());
	assert(wrc == (ssize_t) http_body.size());
}

static void cmd_info_response(const string& http_body)
{
	cmd_stdout_response(http_body);
}

static void cmd_exec_response(const string& http_body)
{
	Ora::ExecOutput oresp;
	if (!oresp.ParseFromString(http_body)) {
		fprintf(stderr, "Exec: protobuf decode failed\n");
		exit(1);
	}

	// TODO
	printf("EXEC response successfully received\n");
}

static string cmd_exec_encode()
{
	Ora::ExecInput oreq;

	oreq.set_chain_id(Ora::ExecInput_ChainId_BITCOIN);

	assert(oreq.IsInitialized() == true);

	string s;
	if (!oreq.SerializeToString(&s))
		return "";

	return s;
}

static void
err(const char *msg)
{
	fputs(msg, stderr);
}

static void
err_openssl(const char *func)
{
	fprintf (stderr, "%s failed:\n", func);

	/* This is the OpenSSL function that prints the contents of the
	 * error stack to the specified file handle. */
	ERR_print_errors_fp (stderr);

	exit(1);
}

/* See http://archives.seul.org/libevent/users/Jan-2013/msg00039.html */
static int cert_verify_callback(X509_STORE_CTX *x509_ctx, void *arg)
{
	char cert_str[256];
	const char *host = (const char *) arg;
	const char *res_str = "X509_verify_cert failed";

	/* This is the function that OpenSSL would call if we hadn't called
	 * SSL_CTX_set_cert_verify_callback().  Therefore, we are "wrapping"
	 * the default functionality, rather than replacing it. */
	int ok_so_far = 0;

	X509 *server_cert = NULL;

	ok_so_far = X509_verify_cert(x509_ctx);

	server_cert = X509_STORE_CTX_get_current_cert(x509_ctx);

	if (ok_so_far) {
		res_str = "MatchNotFound";
	}

	X509_NAME_oneline(X509_get_subject_name (server_cert),
			  cert_str, sizeof (cert_str));

	printf("Got '%s' for hostname '%s' and certificate:\n%s\n",
	       res_str, host, cert_str);
	return 0;
}

static bool init_libssl(SSL_CTX **ssl_ctx_out, const string& crt,
			const string& host)
{
	SSL_CTX *ssl_ctx = NULL;

	// Initialize OpenSSL
	SSL_library_init();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	/* This isn't strictly necessary... OpenSSL performs RAND_poll
	 * automatically on first use of random number generator. */
	int r = RAND_poll();
	if (r == 0) {
		err_openssl("RAND_poll");
		return false;
	}

	/* Create a new OpenSSL context */
	ssl_ctx = SSL_CTX_new(SSLv23_method());
	if (!ssl_ctx) {
		err_openssl("SSL_CTX_new");
		return false;
	}

	/* Attempt to use the system's trusted root certificates.
	 * (This path is only valid for Debian-based systems.) */
	if (1 != SSL_CTX_load_verify_locations(ssl_ctx, crt.c_str(), NULL)) {
		err_openssl("SSL_CTX_load_verify_locations");
		SSL_CTX_free(ssl_ctx);
		return false;
	}
	/* Ask OpenSSL to verify the server certificate.  Note that this
	 * does NOT include verifying that the hostname is correct.
	 * So, by itself, this means anyone with any legitimate
	 * CA-issued certificate for any website, can impersonate any
	 * other website in the world.  This is not good.  See "The
	 * Most Dangerous Code in the World" article at
	 * https://crypto.stanford.edu/~dabo/pubs/abstracts/ssl-client-bugs.html
	 */
	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
	/* This is how we solve the problem mentioned in the previous
	 * comment.  We "wrap" OpenSSL's validation routine in our
	 * own routine, which also validates the hostname by calling
	 * the code provided by iSECPartners.  Note that even though
	 * the "Everything You've Always Wanted to Know About
	 * Certificate Validation With OpenSSL (But Were Afraid to
	 * Ask)" paper from iSECPartners says very explicitly not to
	 * call SSL_CTX_set_cert_verify_callback (at the bottom of
	 * page 2), what we're doing here is safe because our
	 * cert_verify_callback() calls X509_verify_cert(), which is
	 * OpenSSL's built-in routine which would have been called if
	 * we hadn't set the callback.  Therefore, we're just
	 * "wrapping" OpenSSL's routine, not replacing it. */
	SSL_CTX_set_cert_verify_callback(ssl_ctx, cert_verify_callback,
					  (void *) host.c_str());


	*ssl_ctx_out = ssl_ctx;
	return true;
}

static void
http_request_done(struct evhttp_request *req, void *ctx)
{
	char buffer[256];
	int nread;

	if (req == NULL) {
		/* If req is NULL, it means an error occurred, but
		 * sadly we are mostly left guessing what the error
		 * might have been.  We'll do our best... */
		struct bufferevent *bev = (struct bufferevent *) ctx;
		unsigned long oslerr;
		int printed_err = 0;
		int errcode = EVUTIL_SOCKET_ERROR();
		fprintf(stderr, "some request failed - no idea which one though!\n");
		/* Print out the OpenSSL error queue that libevent
		 * squirreled away for us, if any. */
		while ((oslerr = bufferevent_get_openssl_error(bev))) {
			ERR_error_string_n(oslerr, buffer, sizeof(buffer));
			fprintf(stderr, "%s\n", buffer);
			printed_err = 1;
		}
		/* If the OpenSSL error queue was empty, maybe it was a
		 * socket error; let's try printing that. */
		if (! printed_err)
			fprintf(stderr, "socket error = %s (%d)\n",
				evutil_socket_error_to_string(errcode),
				errcode);
		return;
	}

	int http_status = evhttp_request_get_response_code(req);
	if (http_status != 200)
		fprintf(stderr, "Response line: %d\n", http_status);

	string body;
	while ((nread = evbuffer_remove(evhttp_request_get_input_buffer(req),
	    	buffer, sizeof(buffer))))
		body.append(buffer, nread);

	// fprintf(stderr, "Response bytes: %zu\n", body.size());

	switch (opt_command) {
	case CMD_EXEC:
		cmd_exec_response(body);
		break;
	case CMD_INFO:
		cmd_info_response(body);
		break;
	}
}

static bool http_uri_parse(const string& uri,
			   enum http_scheme_type& scheme,
			   string& host, int& port,
			   string& path)
{
	std::unique_ptr<evhttp_uri, decltype(&evhttp_uri_free)> http_uri(evhttp_uri_parse(uri.c_str()), &evhttp_uri_free);

	if (!http_uri) {
		err("malformed url");
		return false;
	}

	string scheme_str = evhttp_uri_get_scheme(http_uri.get());
	if (scheme_str.empty() || (strcasecmp(scheme_str.c_str(), "https") != 0 &&
	                       strcasecmp(scheme_str.c_str(), "http") != 0)) {
		err("url must be http or https");
		return false;
	}
	if (strcasecmp(scheme_str.c_str(), "https") == 0)
		scheme = HTTPS;
	else
		scheme = HTTP;

	const char *stmp = evhttp_uri_get_host(http_uri.get());
	if (stmp)
		host.assign(stmp);
	if (host.empty()) {
		err("url must have a host");
		return false;
	}

	port = evhttp_uri_get_port(http_uri.get());
	if (port == -1) {
		port = (scheme == HTTP) ? 80 : 443;
	}

	stmp = evhttp_uri_get_path(http_uri.get());
	if (stmp)
		path.assign(stmp);
	if (path.empty()) {
		path = "/";
	}

	return true;
}

static struct evhttp_request *build_http_req(struct bufferevent *bev,
					     bool& method_post,
					     string& uri,
					     const string& host)
{
	struct evhttp_request *req;
	req = evhttp_request_new(http_request_done, bev);
	if (req == NULL) {
		fprintf(stderr, "evhttp_request_new() failed\n");
		return NULL;
	}

	struct evbuffer *OutBuf = evhttp_request_get_output_buffer(req);
	if (!OutBuf) {
		evhttp_request_free(req);
		return NULL;
	}

	string body;
	method_post = false;
	switch (opt_command) {
	case CMD_INFO:
		// do nothing
		break;
	case CMD_EXEC:
		method_post = true;
		uri.append("exec");
		body = cmd_exec_encode();
		break;
	}

	struct evkeyvalq *output_headers=evhttp_request_get_output_headers(req);
	evhttp_add_header(output_headers, "Host", host.c_str());
	evhttp_add_header(output_headers, "Connection", "close");

	if (!body.empty()) {
		char tmpbuf[512];
		snprintf(tmpbuf, sizeof(tmpbuf), "%zu", body.size());
		string clen_str(tmpbuf);
		evhttp_add_header(output_headers, "Content-Length", clen_str.c_str());

		evbuffer_add(OutBuf, body.c_str(), body.size());
	}

	return req;
}

int
main(int argc, char **argv)
{
	int r;

	/* Parsing of commandline parameters */
	argp_parse(&argp, argc, argv, ARGP_IN_ORDER, NULL, NULL);

	string uri;
	string host, path;
	string crt("/etc/ssl/certs/ca-certificates.crt");
	bool method_post = false;
	int port = -1;

	SSL_CTX *ssl_ctx = NULL;
	SSL *ssl = NULL;
	struct bufferevent *bev;
	struct evhttp_request *req;
	struct evhttp_connection *evcon = NULL;
	struct bufferevent *under_bev = NULL;

	int ret = 0;
	enum http_scheme_type type = HTTP;

	if (opt_url.empty())
		goto error;

	if (!http_uri_parse(opt_url, type, host, port, path))
		goto error;

	uri = path;

	if (!init_libssl(&ssl_ctx, crt, host))
		goto error;

	// Create event base
	base = event_base_new();
	if (!base) {
		perror("event_base_new()");
		goto error;
	}

	// Create OpenSSL bufferevent and stack evhttp on top of it
	ssl = SSL_new(ssl_ctx);
	if (ssl == NULL) {
		err_openssl("SSL_new()");
		goto error;
	}

	#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	// Set hostname for SNI extension
	SSL_set_tlsext_host_name(ssl, host.c_str());
	#endif

	// For simplicity, we let DNS resolution block. Everything else should be
	// asynchronous though.
	evcon = evhttp_connection_base_new(base, NULL, host.c_str(), port);
	if (evcon == NULL) {
		fprintf(stderr, "evhttp_connection_base_bufferevent_new() failed\n");
		goto error;
	}

	under_bev = evhttp_connection_get_bufferevent(evcon);
	if (type == HTTPS) {
		bev = bufferevent_openssl_filter_new(base, under_bev, ssl,
			BUFFEREVENT_SSL_CONNECTING,
			BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);

		if (bev == NULL) {
			fprintf(stderr, "bufferevent_openssl_socket_new() failed\n");
			goto error;
		}
	} else
		bev = under_bev;

	req = build_http_req(bev, method_post, uri, host);
	if (!req)
		goto error;

	r = evhttp_make_request(evcon, req, method_post ? EVHTTP_REQ_POST : EVHTTP_REQ_GET, uri.c_str());
	if (r != 0) {
		fprintf(stderr, "evhttp_make_request() failed\n");
		goto error;
	}

	event_base_dispatch(base);
	goto cleanup;

error:
	ret = 1;
cleanup:
	if (evcon)
		evhttp_connection_free(evcon);
	event_base_free(base);

	if (ssl_ctx)
		SSL_CTX_free(ssl_ctx);
	if (type == HTTP && ssl)
		SSL_free(ssl);
	EVP_cleanup();
	ERR_free_strings();

#ifdef EVENT__HAVE_ERR_REMOVE_THREAD_STATE
	ERR_remove_thread_state(NULL);
#else
	ERR_remove_state(0);
#endif
	CRYPTO_cleanup_all_ex_data();

	sk_SSL_COMP_free(SSL_COMP_get_compression_methods());

	return ret;
}

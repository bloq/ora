
#include <string>
#include <memory>
#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "oraapi.h"

using namespace std;

enum http_scheme_type {
	HTTP,
	HTTPS
};

namespace Ora {

struct http_req_context {
	struct bufferevent *bev;
	int http_status;
	std::string *output_data;

	http_req_context() : bev(NULL), http_status(-1), output_data(NULL) {}
};

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

	/* This isn't strictly necessary... OpenSSL performs RAND_poll
	 * automatically on first use of random number generator. */
	int r = RAND_poll();
	if (r == 0)
		return false;

	/* Create a new OpenSSL context */
	ssl_ctx = SSL_CTX_new(SSLv23_method());
	if (!ssl_ctx)
		return false;

	/* Attempt to use the system's trusted root certificates.
	 * (This path is only valid for Debian-based systems.) */
	if (1 != SSL_CTX_load_verify_locations(ssl_ctx, crt.c_str(), NULL)) {
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
http_request_done(struct evhttp_request *req, void *ctx_)
{
	struct http_req_context *ctx = (struct http_req_context *) ctx_;
	char buffer[256];
	int nread;

	if (req == NULL) {
		/* If req is NULL, it means an error occurred, but
		 * sadly we are mostly left guessing what the error
		 * might have been.  We'll do our best... */
		struct bufferevent *bev = ctx->bev;
		unsigned long oslerr;
		int printed_err = 0;
		int errcode = EVUTIL_SOCKET_ERROR();

		/* Print out the OpenSSL error queue that libevent
		 * squirreled away for us, if any. */
		while ((oslerr = bufferevent_get_openssl_error(bev))) {
			ctx->http_status = (int)(-((long)oslerr));
			printed_err = 1;
		}
		/* If the OpenSSL error queue was empty, maybe it was a
		 * socket error; let's try printing that. */
		if (! printed_err)
			ctx->http_status = -errcode;
		return;
	}

	ctx->http_status = evhttp_request_get_response_code(req);

	ctx->output_data->clear();
	while ((nread = evbuffer_remove(evhttp_request_get_input_buffer(req),
		buffer, sizeof(buffer))))
		ctx->output_data->append(buffer, nread);
}

static bool http_uri_parse(const string& uri,
			   enum http_scheme_type& scheme,
			   string& host, int& port,
			   string& path)
{
	std::unique_ptr<evhttp_uri, decltype(&evhttp_uri_free)> http_uri(evhttp_uri_parse(uri.c_str()), &evhttp_uri_free);

	if (!http_uri)
		return false;

	string scheme_str = evhttp_uri_get_scheme(http_uri.get());
	if (scheme_str.empty() || (strcasecmp(scheme_str.c_str(), "https") != 0 &&
	                       strcasecmp(scheme_str.c_str(), "http") != 0))
		return false;
	if (strcasecmp(scheme_str.c_str(), "https") == 0)
		scheme = HTTPS;
	else
		scheme = HTTP;

	const char *stmp = evhttp_uri_get_host(http_uri.get());
	if (stmp)
		host.assign(stmp);
	if (host.empty())
		return false;

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

static struct evhttp_request *build_http_req(struct http_req_context *ctx,
					     const string& host,
					     const string& body,
					     const string& ctype = "")
{
	struct evhttp_request *req;
	req = evhttp_request_new(http_request_done, ctx);
	if (req == NULL)
		return NULL;

	struct evbuffer *OutBuf = evhttp_request_get_output_buffer(req);
	if (!OutBuf) {
		evhttp_request_free(req);
		return NULL;
	}

	struct evkeyvalq *output_headers=evhttp_request_get_output_headers(req);
	evhttp_add_header(output_headers, "Host", host.c_str());
	evhttp_add_header(output_headers, "Connection", "close");
	if (!ctype.empty())
		evhttp_add_header(output_headers, "Content-Type", ctype.c_str());

	if (!body.empty()) {
		char tmpbuf[512];
		snprintf(tmpbuf, sizeof(tmpbuf), "%zu", body.size());
		string clen_str(tmpbuf);
		evhttp_add_header(output_headers, "Content-Length", clen_str.c_str());

		evbuffer_add(OutBuf, body.c_str(), body.size());
	}

	return req;
}


bool Client::open(const std::string& endpoint_url)
{
	string uri;
	string host, path;
	string crt(crt_path);
	int port = -1;

	struct bufferevent *under_bev = NULL;

	enum http_scheme_type type = HTTP;

	if (endpoint_url.empty())
		return false;

	if (!http_uri_parse(endpoint_url, type, host, port, path))
		return false;

	endpoint_uri = path;
	endpoint_host = host;

	if (!init_libssl(&ssl_ctx, crt, host))
		return false;

	// Create OpenSSL bufferevent and stack evhttp on top of it
	ssl = SSL_new(ssl_ctx);
	if (!ssl)
		return false;

	#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	// Set hostname for SNI extension
	SSL_set_tlsext_host_name(ssl, host.c_str());
	#endif

	// For simplicity, we let DNS resolution block. Everything else should be
	// asynchronous though.
	evcon = evhttp_connection_base_new(base, NULL, host.c_str(), port);
	if (evcon == NULL)
		return false;

	under_bev = evhttp_connection_get_bufferevent(evcon);
	if (type == HTTPS) {
		bev = bufferevent_openssl_filter_new(base, under_bev, ssl,
			BUFFEREVENT_SSL_CONNECTING,
			BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);

		if (bev == NULL)
			return false;
	} else
		bev = under_bev;

	return true;
}


bool Client::call(const std::string& uri, bool method_post,
                  const std::string& in_data, std::string& out_data)
{
	struct http_req_context ctx;
	struct evhttp_request *req;
	ctx.output_data = &out_data;

	req = build_http_req(&ctx, endpoint_host, in_data);
	if (!req)
		return false;

	int r = evhttp_make_request(evcon, req,
			        method_post ? EVHTTP_REQ_POST : EVHTTP_REQ_GET,
				uri.c_str());
	if (r != 0)
		return false;

	event_base_dispatch(base);

	return (ctx.http_status == 200);
}

bool Client::info(UniValue& meta)
{
	std::string in_data;
	std::string out_data;
	bool rc = call(endpoint_uri, false, in_data, out_data);
	if (!rc)
		return false;

	meta.clear();
	return meta.read(out_data);
}

bool Client::exec(const ExecInput& ei, ExecOutput& eo)
{
	std::string in_data;
	if (!ei.IsInitialized() || !ei.SerializeToString(&in_data))
		return false;

	std::string out_data;
	bool rc = call(endpoint_uri + "exec", true, in_data, out_data);
	if (!rc)
		return false;

	if (!eo.ParseFromString(out_data))
		return false;

	return true;
}

void execInputAdd(ExecInput& ei, const std::string& data)
{
	vector<unsigned char> md(SHA256_DIGEST_LENGTH);
	SHA256((const unsigned char *) &data[0], data.size(), &md[0]);

	ei.add_input_hashes(&md[0], md.size());
	ei.add_input_data(data);
}

void execInputAdd(ExecInput& ei, const void *data, size_t data_len)
{
	vector<unsigned char> md(SHA256_DIGEST_LENGTH);
	SHA256((const unsigned char *) data, data_len, &md[0]);

	ei.add_input_hashes(&md[0], md.size());
	ei.add_input_data(data, data_len);
}

void init_library()
{
	// Initialize OpenSSL
	SSL_library_init();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
}

} // namespace Ora


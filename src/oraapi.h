#ifndef __ORAAPI_H__
#define __ORAAPI_H__

#include <string>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/http.h>
#include <openssl/ssl.h>
#include <univalue.h>

#include "oraapi.pb.h"

#define ORA_DEF_CRT_PATH "/etc/ssl/certs/ca-certificates.crt"

namespace Ora {

class Client {
private:
	struct event_base *base;
	struct evhttp_connection *evcon;
	struct bufferevent *bev;

	std::string endpoint_uri;
	std::string endpoint_host;
	std::string crt_path;
	SSL_CTX *ssl_ctx;
	SSL *ssl;

public:
	Client(struct event_base *base_, const std::string& crt_path_ = ORA_DEF_CRT_PATH) {
		base = base_;
		evcon = NULL;
		bev = NULL;
		crt_path = crt_path_;
		ssl_ctx = NULL;
		ssl = NULL;
	}
	~Client() {
		if (ssl)
			SSL_free(ssl);
		if (ssl_ctx)
			SSL_CTX_free(ssl_ctx);
		if (evcon)
			evhttp_connection_free(evcon);

		// Do not free: base, bev
	}

	bool open(const std::string& endpoint_url);
	bool call(const std::string& path, bool method_post,
		  const std::string& in_data,
		  std::string& out_data);

	bool info(UniValue& meta);
	bool exec(const ExecInput& ei, ExecOutput& eo);
};

extern void execInputAdd(ExecInput& ei, const std::string& data);
extern void execInputAdd(ExecInput& ei, const void *data, size_t data_len);
extern void init_library();

} // namespace Ora

#endif // __ORAAPI_H__

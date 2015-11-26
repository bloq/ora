
#include "ora-config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <memory>
#include <cstdint>
#include <iostream>
#include <fcntl.h>
#include <string>
#include <vector>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <signal.h>
#include <univalue.h>
#include <evhttp.h>
#include "oraapi.pb.h"
#include "sandbox.h"

using namespace std;

#define DEFAULT_LISTEN_ADDR "0.0.0.0"
#define DEFAULT_LISTEN_PORT 12014

static const size_t MAX_HTTP_BODY = 16 * 1000 * 1000;
static const uint32_t STACK_SIZE = 64 * 1024;


bool loadRawData(machine& mach, const string& filename)
{
	// open and mmap input file
	mfile pf(filename);
	if (!pf.open(O_RDONLY))
		return false;

	static unsigned int dataCount = 0;
	char tmpstr[32];

	// alloc new data memory range
	sprintf(tmpstr, "data%u", dataCount++);
	size_t sz = pf.st.st_size;
	addressRange *rdr = new addressRange(tmpstr, sz);

	// copy mmap'd data into local buffer
	rdr->buf.assign((char *) pf.data, sz);
	rdr->updateRoot();

	// add to global memory map
	return mach.mapInsert(rdr);
}

static void usage(const char *progname)
{
	fprintf(stderr,
		"Usage: %s [options]\n"
		"\n"
		"options:\n"
		"-g <port>\t\tWait for GDB connection on given port\n"
		"-p <file>\t\tWrite gprof formatted profile data to <file>\n"
		,
		progname);
}

#if 0
static void printMemMap(machine &mach)
{
	for (unsigned int i = 0; i < mach.memmap.size(); i++) {
		addressRange *ar = mach.memmap[i];
		fprintf(stderr, "%s %08x-%08x %s\n",
			ar->readOnly ? "ro" : "rw", ar->start, ar->end,
			ar->name.c_str());
	}
}

static void addStackMem(machine& mach)
{
	// alloc r/w memory range
	addressRange *rdr = new addressRange("stack", STACK_SIZE);

	rdr->buf.resize(STACK_SIZE);
	rdr->updateRoot();
	rdr->readOnly = false;

	// add memory range to global memory map
	mach.mapInsert(rdr);

	// set SR #7 to now-initialized stack vaddr
	mach.cpu.asregs.sregs[7] = rdr->end;
}

static void addMapDescriptor(machine& mach)
{
	// fill list from existing memory map
	vector<struct mach_memmap_ent> desc;
	mach.fillDescriptors(desc);

	// add entry for the mapdesc range to be added to memory map
	struct mach_memmap_ent mme_self;
	memset(&mme_self, 0, sizeof(mme_self));
	desc.push_back(mme_self);

	// add blank entry for list terminator
	struct mach_memmap_ent mme_end;
	memset(&mme_end, 0, sizeof(mme_end));
	desc.push_back(mme_end);

	// calc total region size
	size_t sz = sizeof(mme_end) * desc.size();

	// manually fill in mapdesc range descriptor
	mme_self.length = sz;
	strcpy(mme_self.tags, "ro,mapdesc,");

	// build entry for global memory map
	addressRange *ar = new addressRange("mapdesc", sz);

	// allocate space for descriptor array
	ar->buf.resize(sz);
	ar->updateRoot();

	// copy 'desc' array into allocated memory space
	unsigned int i = 0;
	for (vector<struct mach_memmap_ent>::iterator it = desc.begin();
	     it != desc.end(); it++, i++) {
		struct mach_memmap_ent& mme = (*it);
		memcpy(&ar->buf[i * sizeof(mme)], &mme, sizeof(mme));
	}

	// add memory range to global memory map
	mach.mapInsert(ar);

	// set SR #6 to now-initialized mapdesc start vaddr
	mach.cpu.asregs.sregs[6] = ar->start;
}
#endif

static void gatherOutput(machine& mach, const string& outFilename)
{
	if (!outFilename.size())
		return;

	uint32_t vaddr = mach.cpu.asregs.sregs[6];
	uint32_t length = mach.cpu.asregs.sregs[7];
	if (!vaddr || !length)
		return;

	char *p = (char *) mach.physaddr(vaddr, length);
	if (!p) {
		fprintf(stderr, "Sim exception %d (%s) upon output\n",
			SIGBUS,
			strsignal(SIGBUS));
		exit(EXIT_FAILURE);
	}

	int fd;
	if (outFilename == "-") {
		fd = STDOUT_FILENO;
	} else {
		fd = open(outFilename.c_str(),
			  O_WRONLY | O_CREAT | O_TRUNC, 0666);
		if (fd < 0) {
			perror(outFilename.c_str());
			exit(EXIT_FAILURE);
		}
	}

	while (length > 0) {
		ssize_t bytes = write(fd, p, length);
		if (bytes < 0) {
			perror(outFilename.c_str());
			exit(EXIT_FAILURE);
		}

		length -= bytes;
		p += bytes;
	}

	close(fd);
}

static void oraInit(machine& mach, int argc, char **argv,
			string& outFilename, string& gmonFilename,
			uint32_t& gdbPort)
{
	int opt;
	while ((opt = getopt(argc, argv, "g:p:")) != -1) {
		switch(opt) {
		case 'g':
			gdbPort = atoi(optarg);
			break;

		case 'p':
			mach.profiling = true;
			gmonFilename = optarg;
			break;

		default:
			usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

}

static char lowNibbleToHex(int nibble)
{
	static const char *hex = "0123456789ABCDEF";
	return hex[nibble & 0xf];
}

static char *lowByteToHex(char *buf, int byte)
{
	buf[0] = lowNibbleToHex(byte >> 4);
	buf[1] = lowNibbleToHex(byte);
	buf[2] = 0;
	return buf;
}

static void sendGdbReply(int fd, const char *msg)
{
	char buf[3];
	char csum = 0;
	unsigned int i;
	ssize_t rc;

	for (i = 0; i < strlen(msg); i++)
		csum += msg[i];

	rc = write(fd, "+$", 2);
	rc = write(fd, msg, strlen(msg));
	rc = write(fd, "#", 1);
	rc = write(fd, lowByteToHex(buf, csum), 2);

	(void) rc;
}

static int hex2int(char c)
{
	switch (c) {
	case '0': case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
		return c - '0';
	case 'A': case 'B': case 'C':
	case 'D': case 'E': case 'F':
		return c - 'A' + 10;
	case 'a': case 'b': case 'c':
	case 'd': case 'e': case 'f':
		return c - 'a' + 10;
	default:
		return -1;
	}
}

static char *word2hex(char *buf, int word)
{
	int i;
	for (i = 0; i < 8; i++)
		buf[i] = lowNibbleToHex(word >> (28 - i*4));
	buf[8] = 0;
	return buf;
}

static uint32_t readHexValueFixedLength(char *buffer,
					int *index, int length)
{
	int n = 0;
	int i = *index;

	while (length--)
	{
		char c = buffer[i++];
		int v = hex2int(c);
		n = (n << 4) + v;
	}
	*index = i;
	return n;
}

static uint32_t readDelimitedHexValue(char *buffer, int *index)
{
	int n = 0, v;
	int i = *index;
	do {
		char c = buffer[i++];
		v = hex2int(c);
		if (v >= 0)
			n = (n << 4) + v;
	} while (v >= 0);
	*index = i;
	return n;
}

static int gdb_main_loop (uint32_t& gdbPort, machine& mach)
{
	int sockfd, newsockfd, on;
	struct sockaddr_in serv_addr, cli_addr;
	socklen_t clilen;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("ERROR opening socket");
		return EXIT_FAILURE;
	}
	on = 1;
	setsockopt(sockfd, SOL_SOCKET,
		   SO_REUSEADDR, (char*)&on, sizeof(on));
	on = 1;
	setsockopt(sockfd, SOL_SOCKET,
		   SO_KEEPALIVE, (char*)&on, sizeof(on));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(gdbPort);
	if (bind(sockfd,
		 (struct sockaddr *) &serv_addr,
		 sizeof(serv_addr)) < 0) {
		close(sockfd);
		perror("ERROR on binding");
		return EXIT_FAILURE;
	}
	listen(sockfd,1);
	clilen = sizeof(cli_addr);
	newsockfd = accept(sockfd,
			   (struct sockaddr *) &cli_addr,
			   &clilen);

	while (1) {
		char buffer[255];
		char reply[1024];
		ssize_t wrc;
		int i = 0, n = read(newsockfd,buffer,255);
		buffer[n] = 0;
		if (n <= 0) {
			perror("ERROR reading from socket");
			return EXIT_FAILURE;
		}
		while (buffer[i]) {
			switch (buffer[i]) {
			case '+':
				i++;
				break;
			case '-':
				// resend last response
				i++;
				break;
			case '$':
			{
				switch (buffer[++i]) {
				case '?':
					sendGdbReply(newsockfd, "S05");
					i += 4;
					break;
				case 'c':
					wrc = write(newsockfd, "+", 1);
					sim_resume(mach);
					// FIXME.. assuming BREAK for now
					sendGdbReply(newsockfd, "S05");
					mach.cpu.asregs.regs[16] -= 2;
					i += 4;

					(void) wrc;
					break;
				case 'g':
				{
					int ri;
					for (ri = 0; ri < 17; ri++)
					{
						uint32_t rv = mach.cpu.asregs.regs[ri];
						sprintf(&reply[ri * 8],
							"%02x%02x%02x%02x",
							(rv >> 0) & 0xff,
							(rv >> 8) & 0xff,
							(rv >> 16) & 0xff,
							(rv >> 24) & 0xff);
					}
					sendGdbReply(newsockfd, reply);
					i += 4;
				}
				break;
				case 'm':
				{
					uint32_t addr =
						readDelimitedHexValue(buffer, &++i);
					uint32_t length =
						readDelimitedHexValue(buffer, &i);
					char *p = (char *) mach.physaddr(addr, length);
					reply[0] = 0;
					while (length-- > 0)
					{
						int c = *p++;
						char buf[3];
						strcat(reply, lowByteToHex(buf, c));
					}
					sendGdbReply(newsockfd, reply);
					i += 2;
				}
				break;
				case 'M':
				{
					uint32_t addr =
						readDelimitedHexValue(buffer, &++i);
					uint32_t length =
						readDelimitedHexValue(buffer, &i);
					char *p = (char *) mach.physaddr(addr, length);
					while (length-- > 0)
						*p++ = readHexValueFixedLength(buffer, &i, 2);
					sendGdbReply(newsockfd, "OK");
					i += 2;
				}
				break;
				case 'p':
				{
					int r = readDelimitedHexValue(buffer, &++i);
					char buf[9];
					sendGdbReply(newsockfd,
						     word2hex(buf, mach.cpu.asregs.regs[r]));
					i += 2;
				}
				break;
				case 'P':
				{
					int r = readDelimitedHexValue(buffer, &++i);
					word v = readDelimitedHexValue(buffer, &i);
					mach.cpu.asregs.regs[r] = v;
					sendGdbReply(newsockfd, "S05");
					i += 2;
				}
				break;
				default:
					while (buffer[++i] != '#');
					i += 3;
					wrc = write(newsockfd,"+$#00", 5);

					(void) wrc;
					break;
				}
			}
			break;
			default:
				i++;
			}
		}
	}
}

static void saveProfileData(machine mach, string gmonFilename)
{
	FILE *f = fopen (gmonFilename.c_str(), "w");

	if (! f) {
		perror("ERROR opening profile output data file");
		exit (EXIT_FAILURE);
	}

	// Write gmon file header.
	fputs ("gmon", f);
	int addr = 1, val = 0;
	uint64_t arc;
	char code = 2;
	fwrite (&addr, 1, 4, f);
	fwrite (&val, 1, 4, f);
	fwrite (&val, 1, 4, f);
	fwrite (&val, 1, 4, f);

	// Write call graph records.
	code = 1;
	for (gprof_cg_map_t::iterator it = mach.gprof_cg_data.begin();
	     it != mach.gprof_cg_data.end(); ++it)
	{
		arc = it->first;
		val = it->second;
		fwrite (&code, 1, 1, f);
		fwrite (&arc, 1, 8, f);
		fwrite (&val, 1, 4, f);
	}

	// Write basic block counts.
	code = 2;
	fwrite (&code, 1, 1, f);
	val = mach.gprof_bb_data.size();
	fwrite (&val, 1, 4, f); // number of elements
	for (gprof_bb_map_t::iterator it = mach.gprof_bb_data.begin();
	     it != mach.gprof_bb_data.end(); ++it)
	{
		addr = it->first;
		val = it->second;
		fwrite (&addr, 1, 4, f);
		fwrite (&val, 1, 4, f);
	}

	fclose (f);
}

void rpc_home(evhttp_request *req, void *)
{
	auto *OutBuf = evhttp_request_get_output_buffer(req);
	if (!OutBuf)
		return;

	UniValue rv(UniValue::VARR);

	UniValue api_obj(UniValue::VOBJ);
	api_obj.pushKV("name", "ora/1");		// service ora, ver 1
	api_obj.pushKV("pricing-type", NullUniValue);

	rv.push_back(api_obj);

	std::string body = rv.write(2) + "\n";

	// hash output
	vector<unsigned char> md(SHA256_DIGEST_LENGTH);
	SHA256((const unsigned char *) body.c_str(), body.size(), &md[0]);

	evbuffer_add(OutBuf, body.c_str(), body.size());

	struct evkeyvalq * kv = evhttp_request_get_output_headers(req);
	evhttp_add_header(kv, "Content-Type", "application/json");
	evhttp_add_header(kv, "Server", "orad/" PACKAGE_VERSION);
	evhttp_add_header(kv, "ETag", HexStr(md).c_str());

	evhttp_send_reply(req, HTTP_OK, "", OutBuf);
};

static bool read_http_input(evhttp_request *req, string& body)
{
	// absorb HTTP body input
	struct evbuffer *buf = evhttp_request_get_input_buffer(req);

	size_t buflen;
	while ((buflen = evbuffer_get_length(buf))) {
		if ((body.size() + buflen) > MAX_HTTP_BODY) {
			evhttp_send_error(req, 400, "input too large");
			return false;
		}

		vector<unsigned char> tmp_buf(buflen);
		int n = evbuffer_remove(buf, &tmp_buf[0], buflen);
		if (n > 0)
			body.append((const char *) &tmp_buf[0], n);
	}

	return true;
}

void rpc_exec(evhttp_request *req, void *)
{
	// absorb HTTP body input
	string body;
	if (!read_http_input(req, body))
		return;

	// decode protobuf msg request
	Ora::ExecInput oreq;
	if (!oreq.ParseFromString(body) || !oreq.IsInitialized()) {
		evhttp_send_error(req, 400, "protobuf decode failed");
		return;
	}

	// no need for raw wire data anymore
	body.clear();

	// FIXME - actually do something...

	// prep HTTP response output
	auto *OutBuf = evhttp_request_get_output_buffer(req);
	if (!OutBuf)
		return;

	// prep protobuf msg response
	Ora::ExecOutput oresp;
	oresp.set_return_code(0);
	oresp.set_sha256("froo");
	if (!oresp.IsInitialized() || !oresp.SerializeToString(&body)) {
		evhttp_send_error(req, 500, "internal checks failed");
		return;
	}

	// hash output
	vector<unsigned char> md(SHA256_DIGEST_LENGTH);
	SHA256((const unsigned char *) body.c_str(), body.size(), &md[0]);

	// HTTP headers
	struct evkeyvalq * kv = evhttp_request_get_output_headers(req);
	evhttp_add_header(kv, "Content-Type", "application/protobuf");
	evhttp_add_header(kv, "Server", "orad/" PACKAGE_VERSION);
	evhttp_add_header(kv, "ETag", HexStr(md).c_str());

	// finalize, send everything
	evhttp_send_reply(req, HTTP_OK, "", OutBuf);
};

void rpc_unknown(evhttp_request *req, void *)
{
	auto *OutBuf = evhttp_request_get_output_buffer(req);
	if (!OutBuf)
		return;
	evbuffer_add_printf(OutBuf, "<html><body><center><h1>404 not found</h1></center></body></html>");
	evhttp_send_error(req, 404, "not found");
};

int main(int argc, char *argv[])
{
	if (!event_init())
	{
		std::cerr << "Failed to init libevent." << std::endl;
		return -1;
	}

	char const SrvAddress[] = DEFAULT_LISTEN_ADDR;
	std::uint16_t SrvPort = DEFAULT_LISTEN_PORT;
	std::unique_ptr<evhttp, decltype(&evhttp_free)> Server(evhttp_start(SrvAddress, SrvPort), &evhttp_free);
	if (!Server)
	{
		std::cerr << "Failed to init http server." << std::endl;
		return -1;
	}

	evhttp_set_cb(Server.get(), "/", rpc_home, nullptr);
	evhttp_set_cb(Server.get(), "/exec", rpc_exec, nullptr);
	evhttp_set_gencb(Server.get(), rpc_unknown, nullptr);

	machine mach;
	string outFilename, gmonFilename;
	uint32_t gdbPort = 0;

	oraInit(mach, argc, argv, outFilename, gmonFilename, gdbPort);

	if (gdbPort)
		gdb_main_loop(gdbPort, mach);
	else
		sim_resume(mach);

	if (event_dispatch() == -1)
	{
		std::cerr << "Failed to run message loop." << std::endl;
		return -1;
	}

	gatherOutput(mach, outFilename);

	if (mach.profiling)
		saveProfileData(mach, gmonFilename);

	return 0;
}


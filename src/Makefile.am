
EXTRA_DIST = oraapi.proto

noinst_PROGRAMS = sandbox oracli orad gen-sum pbmaker

noinst_LIBRARIES = libmoxievm.a libsandbox.a liboraapi.a

AM_CXXFLAGS = -std=gnu++0x

libmoxievm_a_SOURCES = \
	machine.cc \
	moxie.h \
	moxie.cc \
	moxievm.h

libsandbox_a_SOURCES = \
	sandbox.h \
	util.cc

sandbox_SOURCES = \
	elf.cc \
	sandbox.cc
sandbox_LDADD = libmoxievm.a libsandbox.a $(ELF_LIBS) $(CRYPTO_LIBS)

liboraapi_a_SOURCES = \
	oraapi.pb.cc oraapi.pb.h \
	oraapi.h \
	libhttp.cc

pbmaker_SOURCES = pbmaker.cc
pbmaker_LDADD = liboraapi.a $(CRYPTO_LIBS) $(EVENT_LIBS) $(UNIVALUE_LIBS) $(PROTOBUF_LIBS)

oracli_SOURCES = \
	oracli.cc
oracli_LDADD = liboraapi.a $(CRYPTO_LIBS) $(EVENT_LIBS) $(UNIVALUE_LIBS) $(PROTOBUF_LIBS) $(SSL_LIBS)

orad_SOURCES = \
	elf.cc \
	moxie.h \
	moxie.cc \
	orad.cc
orad_LDADD = liboraapi.a libmoxievm.a libsandbox.a $(ELF_LIBS) $(CRYPTO_LIBS) $(EVENT_LIBS) $(UNIVALUE_LIBS) $(PROTOBUF_LIBS)

gen_sum_SOURCES = gen-sum.cc
gen_sum_LDADD = libsandbox.a $(CRYPTO_LIBS)

BUILT_SOURCES = oraapi.pb.cc oraapi.pb.h
CLEANFILES = oraapi.pb.cc oraapi.pb.h

oraapi.pb.cc: oraapi.proto
	protoc --cpp_out=. oraapi.proto
oraapi.pb.h: oraapi.proto
	protoc --cpp_out=. oraapi.proto


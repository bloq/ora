
EXTRA_DIST = oraapi.proto

noinst_PROGRAMS = sandbox orad gen-sum

noinst_LIBRARIES = libsandbox.a

AM_CXXFLAGS = -std=gnu++0x

libsandbox_a_SOURCES = \
	sandbox.h \
	util.cc

sandbox_SOURCES = \
	elf.cc \
	machine.cc \
	moxie.h \
	moxie.cc \
	sandbox.cc
sandbox_LDADD = libsandbox.a $(ELF_LIBS) $(CRYPTO_LIBS)

orad_SOURCES = \
	elf.cc \
	machine.cc \
	moxie.h \
	moxie.cc \
	orad.cc \
	oraapi.pb.cc oraapi.pb.h
orad_LDADD = libsandbox.a $(ELF_LIBS) $(CRYPTO_LIBS) $(EVENT_LIBS) $(UNIVALUE_LIBS) $(PROTOBUF_LIBS)

gen_sum_SOURCES = gen-sum.cc
gen_sum_LDADD = libsandbox.a $(CRYPTO_LIBS)

BUILT_SOURCES = oraapi.pb.cc oraapi.pb.h
CLEANFILES = oraapi.pb.cc oraapi.pb.h

oraapi.pb.cc: oraapi.proto
	protoc --cpp_out=. oraapi.proto
oraapi.pb.h: oraapi.proto
	protoc --cpp_out=. oraapi.proto


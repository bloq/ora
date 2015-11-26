
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
	orad.cc
orad_LDADD = libsandbox.a $(ELF_LIBS) $(CRYPTO_LIBS) $(EVENT_LIBS) $(UNIVALUE_LIBS)

gen_sum_SOURCES = gen-sum.cc
gen_sum_LDADD = libsandbox.a $(CRYPTO_LIBS)


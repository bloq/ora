AC_INIT([ora], [0.0.3],
        [http://github.com/bloq/ora/])

AC_PREREQ(2.60)
AC_CONFIG_SRCDIR([src/sandbox.cc])
AM_INIT_AUTOMAKE([gnu])
AC_CONFIG_HEADERS([ora-config.h])

AC_PROG_CXX
AC_PROG_CC
AC_PROG_CPP
AC_PROG_CXXCPP
AC_PROG_INSTALL
AC_PROG_OBJC
AC_PROG_LN_S
AC_PROG_MKDIR_P
AC_PROG_SED
AM_PROG_AS
AC_PATH_TOOL(AR, ar)
AC_PATH_TOOL(RANLIB, ranlib)
AC_PATH_TOOL(STRIP, strip)
AC_CHECK_PROG(MOX_AS, moxiebox-as, moxiebox-as, no)
AC_CHECK_PROG(MOX_AR, moxiebox-ar, moxiebox-ar, no)
AC_CHECK_PROG(MOX_GCC, moxiebox-gcc, moxiebox-gcc, no)
PKG_PROG_PKG_CONFIG

if test x"$MOX_AR" = x"no"; then
    AC_MSG_ERROR([moxiebox-ar is required to build this package])
fi
if test x"$MOX_AS" = x"no"; then
    AC_MSG_ERROR([moxiebox-as is required to build this package])
fi
if test x"$MOX_GCC" = x"no"; then
    AC_MSG_ERROR([moxiebox-gcc is required to build this package])
fi

AC_LANG_PUSH([C++])

AC_CHECK_LIB(elf, elf_getphdrnum, ELF_LIBS=-lelf,AC_MSG_ERROR([Libelf is required to build this package!]))
AC_CHECK_LIB(crypto, SHA256_Update, CRYPTO_LIBS=-lcrypto,AC_MSG_ERROR([Libcrypto is required to build this package!]))
AC_CHECK_LIB(ssl, SSL_new, SSL_LIBS=-lssl,AC_MSG_ERROR([Libssl is required to build this package!]))
AC_CHECK_LIB(event_core, event_base_new, EVENT_LIBS=-levent_core,AC_MSG_ERROR([libevent is required to build this package!]))
AC_CHECK_LIB(event_extra, evhttp_new, EVENT_LIBS="$EVENT_LIBS -levent_extra",AC_MSG_ERROR([libevent_extra is required to build this package!]))
AC_CHECK_LIB(event_openssl, bufferevent_openssl_filter_new, EVENT_LIBS="$EVENT_LIBS -levent_openssl",AC_MSG_ERROR([libevent_openssl is required to build this package!]))

# TODO: improve
UNIVALUE_LIBS="-lunivalue"
PROTOBUF_LIBS="-lprotobuf"

AC_SUBST(ELF_LIBS)
AC_SUBST(CRYPTO_LIBS)
AC_SUBST(SSL_LIBS)
AC_SUBST(EVENT_LIBS)
AC_SUBST(UNIVALUE_LIBS)
AC_SUBST(PROTOBUF_LIBS)
AC_SUBST(MOX_AS)
AC_SUBST(MOX_AR)
AC_SUBST(MOX_GCC)

AC_CONFIG_FILES([
	Makefile
	lib/Makefile
	runtime/Makefile
	src/Makefile
	tests/Makefile])
AC_OUTPUT


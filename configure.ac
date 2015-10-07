AC_INIT([tlsprobe], [0.1], [marco.bellaccini!at!gmail.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
AC_CONFIG_HEADERS([config.h])

PTHREAD_CFLAGS="-pthread"
PTHREAD_LIBS=""
CFLAGS="$CFLAGS $PTHREAD_CFLAGS"


dnl Check if tlsprobe should be installed with filesystem capabilities
AC_PATH_PROG(SETCAP, setcap)
AC_ARG_ENABLE(setcap-install,
  AC_HELP_STRING( [--enable-setcap-install],
                  [install tlsprobe with cap_net_bind_service and cap_net_raw @<:@default=no@:>@]),
    enable_setcap_install=$enableval,enable_setcap_install=no)

AC_MSG_CHECKING(whether to install tlsprobe with cap_net_bind_service and cap_net_raw capabilities)
if test "x$enable_setcap_install" = "xno" ; then
	AC_MSG_RESULT(no)
else
	if test "x$SETCAP" = "x" ; then
		AC_MSG_RESULT(no. Setcap not found)
	else
		AC_MSG_RESULT(yes)
	fi
fi

AM_CONDITIONAL(SETCAP_INSTALL, test x$enable_setcap_install = xyes)

dnl Check if tlsprobe should be installed setuid
AC_ARG_ENABLE(setuid-install,
  AC_HELP_STRING( [--enable-setuid-install],
                  [install tlsprobe as setuid @<:@default=no@:>@]),
    enable_setuid_install=$enableval,enable_setuid_install=no)

AC_MSG_CHECKING(whether to install tlsprobe setuid)
if test "x$enable_setuid_install" = "xno" ; then
	AC_MSG_RESULT(no)
else
	if test "x$enable_setcap_install" = "xyes" ; then
		enable_setuid_install=no
		AC_MSG_RESULT(no; using setcap instead)
	else
		AC_MSG_RESULT(yes)
	fi
fi

AM_CONDITIONAL(SETUID_INSTALL, test x$enable_setuid_install = xyes)
AC_CHECK_FUNCS(setresuid setresgid)


AC_CHECK_HEADERS([stdio.h sys/socket.h netinet/in.h arpa/inet.h netdb.h time.h fcntl.h argp.h errno.h pthread.h],,,[AC_INCLUDES_DEFAULT])
AC_CONFIG_FILES([
 Makefile
 src/Makefile
])
AC_OUTPUT

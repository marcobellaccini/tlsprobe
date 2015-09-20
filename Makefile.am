SUBDIRS = src
dist_pkgdata_DATA=tls-parameters-4.csv ssl-parameters.csv cs_eval.dat

install-exec-hook:
if SETCAP_INSTALL
	$(SETCAP) cap_net_raw,cap_net_bind_service+ep $(DESTDIR)$(bindir)/tlsprobe
	chmod o-rws $(DESTDIR)$(bindir)/tlsprobe
else
if SETUID_INSTALL
	chmod o-rws $(DESTDIR)$(bindir)/tlsprobe
	chmod +s $(DESTDIR)$(bindir)/tlsprobe
endif
endif


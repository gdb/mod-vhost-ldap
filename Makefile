APXS=apxs2
VERSION=`cat VERSION`
DISTFILES=`cat FILES`

all: mod_vhost_ldap.o

install:
	$(APXS) -i mod_vhost_ldap.la

clean:
	rm -f *.o
	rm -f *.lo
	rm -f *.la
	rm -f *.slo
	rm -rf .libs
	rm -rf mod_vhost_ldap-$(VERSION)
	rm -rf mod_vhost_ldap-$(VERSION).tar.gz

mod_vhost_ldap.o: mod_vhost_ldap.c
	$(APXS) -Wc,-Wall -Wc,-Werror -Wc,-g -Wc,-DDEBUG -Wc,-DMOD_VHOST_LDAP_VERSION=\\\"mod_vhost_ldap/$(VERSION)\\\" -c -lldap_r mod_vhost_ldap.c

deb: make clean
	svn export svn+ssh://ondrej@svn.debian.org/svn/modvhostldap mod-vhost-ldap-`cat VERSION`.orig;
	/usr/bin/pdebuild --configfile /home/ondrej/.pbuilderrc.unstable

archive:
	svn export svn+ssh://ondrej@svn.debian.org/svn/modvhostldap/trunk/mod-vhost-ldap/ mod-vhost-ldap-`cat VERSION`;
	rm -rf mod-vhost-ldap-$(VERSION)/debian
	tar czf ../tarballs/mod-vhost-ldap-$(VERSION).tar.gz mod-vhost-ldap-$(VERSION);
	ln -sf mod-vhost-ldap-$(VERSION).tar.gz ../tarballs/mod-vhost-ldap_$(VERSION).orig.tar.gz
	tar cjf ../tarballs/mod-vhost-ldap-$(VERSION).tar.bz2 mod-vhost-ldap-$(VERSION);
	rm -rf mod-vhost-ldap-$(VERSION);

format:
	indent *.c

.PHONY: all install clean archive format

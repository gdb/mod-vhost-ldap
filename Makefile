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
	$(APXS) -Wc,-Wall -Wc,-Werror -Wc,-g -Wc,-DDEBUG -c -lldap_r mod_vhost_ldap.c

archive: clean
	mkdir mod_vhost_ldap-$(VERSION)
	cp $(DISTFILES) mod_vhost_ldap-$(VERSION)
	tar czf mod_vhost_ldap-$(VERSION).tar.gz mod_vhost_ldap-$(VERSION)

format:
	indent *.c

.PHONY: all install clean archive format

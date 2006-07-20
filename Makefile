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

restart:
	> /var/log/apache2/error.log
	/usr/bin/apache2sctl stop
	/usr/bin/apache2sctl start

mod_vhost_ldap.o: mod_vhost_ldap.c

	$(APXS) -Wc,-Wall -Wc,-Werror -Wc,-g -Wc,-DDEBUG -Wc,-DMOD_VHOST_LDAP_VERSION=\\\"mod_vhost_ldap/$(VERSION)\\\" -c -lcrypt -lldap_r mod_vhost_ldap.c
	/usr/bin/apache2sctl restart
	
encclean:
	rm enc
	
encrypt: 
	gcc -Wall encrypt.c -o enc -lcrypt

dtpasswdclean:
	rm dtpasswd
	
dtpasswd:
	gcc -Wall -Werror -l crypt -o dtpasswd dtpasswd.c 

deb: 	
	debuild --no-tgz-check

format:
	indent *.c

.PHONY: all install clean archive format encrypt encclean


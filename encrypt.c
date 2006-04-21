#include <stdio.h>
#include <time.h>
#include <crypt.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void to64(char *s, unsigned long v, int n)
{
    static unsigned char itoa64[] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    while (--n >= 0) {
       *s++ = itoa64[v&0x3f];
        v >>= 6;
    }
}

static char *htenc(const char *clearpasswd) {
	char *res;
	char salt[9];
	(void) srand((int) time((time_t *) NULL));
	to64(&salt[0], rand(), 8);
	salt[8] = '\0';
	res = crypt(clearpasswd, salt);
    return res;
}

int main() { 
    char *orig = "abcd";
    printf("Orig: |%s| \n", orig);
    char *enc = htenc(orig);
    printf("Enc: |%s| \n", enc);
	return 1;

}



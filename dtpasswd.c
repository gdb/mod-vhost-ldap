
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>

#define _XOPEN_SOURCE
#define MD5_CRYPT_ENAB yes
#include <unistd.h>


extern char *crypt (__const char *__key, __const char *__salt);

char *crypt_make_salt (void)
{
        struct timeval tv;
        static char result[40];

        result[0] = '\0';
        strcpy (result, "$1$"); /* magic for the new MD5 crypt() */

        gettimeofday (&tv, (struct timezone *) 0);
        strcat (result, l64a (tv.tv_usec));
        strcat (result, l64a (tv.tv_sec + getpid () + clock ()));

        if (strlen (result) > 3 + 8) result[11] = '\0';

        return result;
}

char *pw_encrypt (const char *clear, const char *salt)
{
        static char cipher[128];
        char *cp = crypt (clear, salt);
        strcpy (cipher, cp);
        return cipher;
}


int main ()
{
	/* for new password, we generate salt 
	 * for check we use encrypted password as salt
	 * char *crpasswd_or_newsalt = crypt_make_salt();
	*/

	const char* msg = "Enter password:";

	char *clear = NULL;
	// clear = "enterclearpasswordhere";
	// or simply get it
	if ( !(clear = getpass(msg)) || strlen(clear) == 0 ) 
	{
	fprintf (stderr, ("You entered no password \n")); 
	return 1;
	}
	else 
	{
		char *crpasswd_or_newsalt = "$1$RG.pRvZh$Q0WZ8clsqtMUBRLFckoQg1";
		char *cipher = pw_encrypt (clear, crpasswd_or_newsalt);

		if (strcmp (cipher, crpasswd_or_newsalt) != 0) 
		{
			fprintf (stderr, (crpasswd_or_newsalt));
			fprintf (stderr, ("\n"));
			fprintf (stderr, ("Incorrect password. Result is:\n"));
			fprintf (stderr, (cipher));
			fprintf (stderr, ("\n"));
			return 1;
		} 
		else 
		{
		fprintf (stderr, ("\n"));
		fprintf (stderr, (crpasswd_or_newsalt));
		fprintf (stderr, ("\n"));
		fprintf (stderr, ("Good password\n"));
		fprintf (stderr, (cipher));
		fprintf (stderr, ("\n"));
		return 0;
		}
	}
}


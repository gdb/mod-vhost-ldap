/***********************************************************
Copyright 1991, 1992 by Stichting Mathematisch Centrum, Amsterdam, The
Netherlands.

                        All Rights Reserved

Permission to use, copy, modify, and distribute this software and its 
documentation for any purpose and without fee is hereby granted, 
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in 
supporting documentation, and that the names of Stichting Mathematisch
Centrum or CWI not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior permission.

STICHTING MATHEMATISCH CENTRUM DISCLAIMS ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS, IN NO EVENT SHALL STICHTING MATHEMATISCH CENTRUM BE LIABLE
FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

******************************************************************/

/* IMGFILE module - Interface to sgi libimg */

/*XXXX This modele should be done better at some point. It should return
** an object of image file class, and have routines to manipulate these
** image files in a neater way (so you can get rgb images off a greyscale
** file, for instance, or do a straight display without having to get the
** image bits into python, etc).
*/

#include "allobjects.h"
#include "modsupport.h"

#include <gl/image.h>

/* #include "sigtype.h" */

static object * ImgfileError;

static char gfname[1024];
static IMAGE *image;

static int error_called;

static imgfile_error(str)
    char *str;
{
    err_setstr(ImgfileError, str);
    error_called = 1;
    return;	/* To imglib, which will return a failure indictaor */
}

static
imgfile_open(args)
    object *args;
{
    char *fname;
    
    if ( !getargs(args, "s", &fname) )
      return 0;
    i_seterror(imgfile_error);
    error_called = 0;
    if ( image != NULL && strcmp(fname, gfname) != 0 ) {
	iclose(image);
	image = NULL;
	gfname[0] = '\0';
    }
    if ( (image=iopen(fname, "r")) == NULL ) {
	/* Error may already be set by imgfile_error */
	if ( !error_called )
	  err_setstr(ImgfileError, "Cannot open image file");
	return 0;
    }
    strcpy(gfname, fname);
    return 1;    
}

static object *
imgfile_read(self, args)
    object *self;
    object *args;
{
    char *fname;
    object *rv;
    int xsize, ysize, zsize;
    char *cdatap;
    long *idatap;
    static short rs[8192], gs[8192], bs[8192];
    int x, y;
    
    if ( !imgfile_open(args) )
      return NULL;
    
    if ( image->colormap != CM_NORMAL ) {
	err_setstr(ImgfileError, "Can only handle CM_NORMAL images");
	return NULL;
    }
    if ( BPP(image->type) != 1 ) {
	err_setstr(ImgfileError, "Cannot handle imgfiles with bpp!=1");
	return NULL;
    }
    xsize = image->xsize;
    ysize = image->ysize;
    zsize = image->zsize;
    if ( zsize != 1 && zsize != 3) {
	err_setstr(ImgfileError, "Can only handle 1 or 3 byte pixels");
	return NULL;
    }

    if ( zsize == 3 ) zsize = 4;
    rv = newsizedstringobject(NULL, xsize*ysize*zsize);
    if ( rv == NULL )
      return NULL;
    cdatap = getstringvalue(rv);
    idatap = (long *)cdatap;
    for ( y=0; y < ysize && !error_called; y++ ) {
	if ( zsize == 1 ) {
	    getrow(image, rs, y, 0);
	    for(x=0; x<xsize; x++ )
	      *cdatap++ = rs[x];
	} else {
	    getrow(image, rs, y, 0);
	    getrow(image, gs, y, 1);
	    getrow(image, bs, y, 2);
	    for(x=0; x<xsize; x++ )
	      *idatap++ = (rs[x] & 0xff)     |
		         ((gs[x] & 0xff)<<8) |
		         ((bs[x] & 0xff)<<16);
	}
    }
    if ( error_called ) {
	DECREF(rv);
	return NULL;
    }
    return rv;
}

static object *
imgfile_getsizes(self, args)
    object *self;
    object *args;
{
    char *fname;
    object *rv;
    
    if ( !imgfile_open(args) )
      return NULL;
    rv = newtupleobject(3);
    if ( rv == NULL )
      return NULL;
    settupleitem(rv, 0, newintobject(image->xsize));
    settupleitem(rv, 1, newintobject(image->ysize));
    settupleitem(rv, 2, newintobject(image->zsize));
    return rv;
}


static struct methodlist imgfile_methods[] = {
    { "getsizes", imgfile_getsizes },
    { "read",     imgfile_read },
    { 0,          0 }
};


void
initimgfile()
{
	object *m, *d;
	m = initmodule("imgfile", imgfile_methods);
	d = getmoduledict(m);
	ImgfileError = newstringobject("imgfile.error");
	if ( ImgfileError == NULL || dictinsert(d,"error",ImgfileError) )
	    fatal("can't define imgfile.error");
}

#! /bin/sh
#
# Drive HTML generation for a Python manual.
#
# This is probably *not* useful outside of the standard Python documentation,
# but suggestions are welcome and should be sent to <python-docs@python.org>.
#
# The first arg is required and is the designation for which manual to build;
# api, ext, lib, ref, or tut.  All other args are passed on to latex2html.

WORKDIR=`pwd`
cd `dirname $0`/..
srcdir=`pwd`
cd $WORKDIR

use_logical_names=true

if [ "$1" = "--numeric" ] ; then
    use_logical_names=false
    shift 1
fi

part=$1; shift 1

TEXINPUTS=$srcdir/$part:$TEXINPUTS
export TEXINPUTS

if [ -d $part ] ; then
    rm -f $part/*.html
else
    mkdir $part
fi

echo "latex2html -no_auto_link" \
 "-up_url '../index.html' -up_title 'Documentation Index'" \
 "-init_file $srcdir/perl/l2hinit.perl -dir $part" \
 "${1:+$@} $srcdir/$part/$part.tex"
latex2html \
 -no_auto_link \
 -up_url '../index.html' \
 -up_title 'Documentation Index' \
 -init_file $srcdir/perl/l2hinit.perl \
 -address '<hr>See <i><a href="about.html">About this document...</a></i> for information on suggesting changes.' \
 -dir $part \
 ${1:+$@} \
 $srcdir/$part/$part.tex || exit $?

cp $part/$part.html $part/index.html

# copy in the stylesheet
echo "cp $srcdir/html/style.css $part/$part.css"
cp $srcdir/html/style.css $part/$part.css || exit $?

if $use_logical_names ; then
    echo "(cd $part; $srcdir/tools/node2label.pl \*.html)"
    cd $part
    $srcdir/tools/node2label.pl *.html || exit $?
else
    echo "Skipping use of logical file names due to --numeric."
fi

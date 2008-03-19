@rem Common file shared between external.bat and external-amd64.bat.  Responsible for
@rem fetching external components into the root\.. buildbot directories.

cd ..
@rem XXX: Force the buildbots to start from a fresh environment.  Will be removed.
if exist bzip2-1.0.3 rd /s/q bzip2-1.0.3
if exist tcltk rd /s/q tcltk
if exist tcltk64 rd /s/q tcltk64
if exist tcl8.4.12 rd /s/q tcl8.4.12
if exist tcl8.4.16 rd /s/q tcl8.4.16
if exist tcl-8.4.18.1 rd /s/q tcl-8.4.18.1
if exist tk8.4.12 rd /s/q tk8.4.12
if exist tk8.4.16 rd /s/q tk8.4.16
if exist tk-8.4.18.1 rd /s/q tk-8.4.18.1
if exist db-4.4.20 rd /s/q db-4.4.20
if exist openssl-0.9.8g rd /s/q openssl-0.9.8g
if exist sqlite-source-3.3.4 rd /s/q sqlite-source-3.3.4    

@rem bzip
if not exist bzip2-1.0.3 svn export http://svn.python.org/projects/external/bzip2-1.0.3

@rem Sleepycat db
if not exist db-4.4.20 svn export http://svn.python.org/projects/external/db-4.4.20-vs9 db-4.4.20

@rem OpenSSL
if not exist openssl-0.9.8g svn export http://svn.python.org/projects/external/openssl-0.9.8g

@rem tcl/tk
if not exist tcl-8.4.18.2 svn export http://svn.python.org/projects/external/tcl-8.4.18.2
if not exist tk-8.4.18.1 svn export http://svn.python.org/projects/external/tk-8.4.18.1


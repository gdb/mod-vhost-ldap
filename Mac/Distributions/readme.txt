How to make a Python-distribution.
----------------------------------

These notes are mainly for myself, or for whoever tries to make a MacPython
distribution when I'm fed up with it. They were last updated for 2.3a1.

- Increase fragment version number in PythonCore and PythonCoreCarbon.
  the fragment number is Python's sys.hexversion, it should be set in the
  "PEF" preferences.
- Increase version number in _versioncheck.py
- Build PythonStandSmall, run once in root folder
- Update NEWS, readme's, Demo:build.html
- fullbuild everything with increase-buildno
- Test with test.regrtest
- Update Numeric and build/install it
- Recompile OSAm and possibly other Contrib stuff
- mkdistr binary.include
- mkdistr dev.include
- make distribution archive with Installer Vise
  Things to make sure of:
  - Version number in toplevel folder name
  - Finder icon positions
  - Version numbers in "Packages..." window
  - Version number in "Installer Settings" -> "Easy Install Text"
  - Version number in "Project" -> Attributes
  - Version number in "Project" -> PostProcess
  - Version number in "Internet" -> "Download Sites"
  - Version number in "Internet" -> "File Groups".
- Check for missing files. Do this by installing everything on your local system,
  and comparing the file tree (CodeWarrior Compare is great for this) with
  :Mac:Distributions:(vise):binary distribution and ....:dev distribution.
  Only the :Lib:plat-xxxx should be missing. Otherwise go back to Installer Vise and
  add the missing stuff. Make sure of all settings for the new files (esp. "where"
  and "gestalt" are easy to miss).
- test on virgin systems (both OS9 and OSX). 
- Remove the local installation so you don't get confused by it.
- checkin everything except PythonX.Y.vct.
- mkdistr src.include
- Rename "src distribution" and stuffit
- Upload
- Update README file in ftp directory
- Change version number in public_html/macpythonversion.txt .
- Update macpython.html
- Send an announcement to:
   pythonmac-sig@python.org
   python-dev@python.org
- Wait a day or so for catastrophic mistakes, then send an announcement to:
   python-announce@python.org
   archivist@info-mac.org
   adcnews@apple.com
   news@macnn.com
   http://www.macupdate.com
   http://guide.apple.com/usindex.lasso
   http://www.apple.com/downloads/macosx/submit
   http://www.versiontracker.com/ (userid Jack.Jansen@oratrix.com)
   http://www.macshareware.net (userid jackjansen)
   Also, check out Stephan Deibels http://pythonology.org/market contact list
- Open PythonX.Y.vct again, use the "remove compressed files" command to trim down
  the size, commit.
- Remove the subdires under (vise) so you don't get confused by them later.
from test_support import verbose
import nis

print 'nis.maps()'
maps = nis.maps()
done = 0
for nismap in maps:
    if verbose:
	print nismap
    mapping = nis.cat(nismap)
    for k, v in mapping.items():
	if verbose:
	    print '    ', k, v
	if not k:
	    continue
	if nis.match(k, nismap) <> v:
	    print "NIS match failed for key `%s' in map `%s'" % (k, nismap)
	else:
	    # just test the one key, otherwise this test could take a
	    # very long time
	    done = 1
	    break
    if done:
	break

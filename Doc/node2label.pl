#!/depot/gnu/plat/bin/perl -i~

# read the labels, then reverse the mappings
require "labels.pl";

%nodes = ();
foreach $label (keys %external_labels) {
  $nodes{$external_labels{$label}} = $label;
}

# collect labels that have been used
%newnames = ();

while (<>) {
  # don't want to do one s/// per line per node
  # so look for lines with hrefs, then do s/// on nodes present
  if (/HREF=\"([^\#\"]*)html[\#\"]/) {
    @parts = split(/HREF\=\"/);
    shift @parts;
    for $node (@parts) {
      $node =~ s/[\#\"].*$//g;
      chop($node);
      if (defined($nodes{$node})) {
	$label = $nodes{$node};
	if (s/HREF=\"$node([\#\"])/HREF=\"$label.html$1/g) {
	  s/HREF=\"$label.html#SECTION\d+/HREF=\"$label.html/g;
	  $newnames{$node} = "$label.html";
	}
      }
    }
  }
  print;
}

foreach $oldname (keys %newnames) {
# or mv
  system("ln -s $oldname $newnames{$oldname}");
}

#LaTeX2HTML Version 96.1 : dot.latex2html-init		-*- perl -*-
#
#  Significantly revised by Fred L. Drake, Jr. <fdrake@acm.org> for use
#  with the Python documentation.
#
#  New name to avoid distributing "dot" files with the Python documentation.
#

package Override;

use Cwd qw(getcwd);


package main;

$HTML_VERSION = 4.0;

$MAX_LINK_DEPTH = 2;
$ADDRESS = '';

$NO_FOOTNODE = 1;
$NUMBERED_FOOTNOTES = 1;

# Python documentation uses section numbers to support references to match
# in the printed and online versions.
#
$SHOW_SECTION_NUMBERS = 1;

$ICONSERVER = '../icons';

# Control where the navigation bars should show up:
$TOP_NAVIGATION = 1;
$BOTTOM_NAVIGATION = 1;
$AUTO_NAVIGATION = 0;

$BODYTEXT = 'bgcolor="#ffffff"';
$CHILDLINE = "\n<p><hr>\n";
$VERBOSITY = 0;

# default # of columns for the indexes
$INDEX_COLUMNS = 2;
$MODULE_INDEX_COLUMNS = 4;


# A little painful, but lets us clean up the top level directory a little,
# and not be tied to the current directory (as far as I can tell).
#
use Cwd;
use File::Basename;
($myname, $mydir, $myext) = fileparse(__FILE__, '\..*');
chop $mydir;			# remove trailing '/'
$mydir = getcwd() . "$dd$mydir"
  unless $mydir =~ s|^/|/|;
$LATEX2HTMLSTYLES = "$mydir$envkey$LATEX2HTMLSTYLES";
push (@INC, $mydir);

($myrootname, $myrootdir, $myext) = fileparse($mydir, '\..*');
chop $myrootdir;


# Hackish way to get the appropriate paper-*/ directory into $TEXINPUTS;
# pass in the paper size (a4 or letter) as the environment variable PAPER
# to add the right directory.  If not given, the current directory is
# added instead for use with HOWTO processing.
#
if (defined $ENV{'PAPER'}) {
    $mytexinputs = "$myrootdir${dd}paper-$ENV{'PAPER'}$envkey";
}
else {
    $mytexinputs = getcwd() . $envkey;
}
$mytexinputs .= "$myrootdir${dd}texinputs";


sub custom_driver_hook{
    #
    # This adds the directory of the main input file to $TEXINPUTS; it
    # seems to be sufficiently general that it should be fine for HOWTO
    # processing.
    #
    my $file = @_[0];
    my($jobname,$dir,$ext) = fileparse($file, '\..*');
    $dir = make_directory_absolute($dir);
    $dir =~ s/$dd$//;
    $TEXINPUTS = "$dir$envkey$mytexinputs";
    print "\nadding $dir to \$TEXINPUTS\n";
}


sub set_icon_size{
    my($name, $w, $h) = @_;
    $iconsizes{$name} = "width=$w height=$h";
}

foreach $name (split(/ /, 'up next previous contents index modules blank')) {
    set_icon_size($name, 32, 32);
}
# The '_motif' is really annoying, and makes the HTML larger with no value
# added, so strip it off:
foreach $name (keys %icons) {
    my $icon = $icons{$name};
    # Strip off the wasteful '_motif':
    $icon =~ s/_motif//;
    # Change the greyed-out icons to be blank:
    $icon =~ s/[a-z]*_gr/blank/;
    $icons{$name} = $icon;
}
$icons{'blank'} = 'blank.' . $IMAGE_TYPE;

$CUSTOM_BUTTONS = '';
$BLANK_ICON = "\n<td>" . img_tag('blank.' . $IMAGE_TYPE) . "</td>";
$BLANK_ICON =~ s/alt="blank"/alt=""/;
$NAV_BGCOLOR = " bgcolor=\"#99CCFF\"";

sub make_nav_sectref{
    my($label,$title) = @_;
    if ($title) {
	return ("<b class=navlabel>$label:</b> "
		. "<span class=sectref>$title</span>\n");
    }
    return '';
}

sub make_nav_panel{
    return ("<table align=center width=\"100%\" cellpadding=0 cellspacing=2>"
	    . "\n<tr>"
	    . "\n<td>$NEXT</td>"
	    . "\n<td>$UP</td>"
	    . "\n<td>$PREVIOUS</td>"
	    . "\n<td align=center$NAV_BGCOLOR width=\"100%\">"
	    . "\n <b class=title>$t_title</b></td>"
	    . ($CONTENTS ? "\n<td>$CONTENTS</td>" : $BLANK_ICON)
	    . "\n<td>$CUSTOM_BUTTONS</td>" # module index
	    . ($INDEX ? "\n<td>$INDEX</td>" : $BLANK_ICON)
	    . "\n</tr></table>"
	    #. "<hr>"
	    . make_nav_sectref("Next", $NEXT_TITLE)
	    . make_nav_sectref("Up", $UP_TITLE)
	    . make_nav_sectref("Previous", $PREVIOUS_TITLE)
	   );
}

sub top_navigation_panel {
    "<div class=navigation>\n"
      . make_nav_panel()
      . '<br><hr></div>';
}

sub bot_navigation_panel {
    "<p>\n<div class=navigation><hr>"
      . make_nav_panel()
      . '</div>';
}

sub add_link {
    # Returns a pair (iconic link, textual link)
    my($icon, $current_file, @link) = @_;
    my($dummy, $file, $title) = split($delim,
				      $section_info{join(' ',@link)});
    if ($title && ($file ne $current_file)) {
        $title = purify($title);
	$title = get_first_words($title, $WORDS_IN_NAVIGATION_PANEL_TITLES);
	return (make_href($file, $icon), make_href($file, "$title"))
	}
    elsif ($icon eq $up_visible_mark && $EXTERNAL_UP_LINK) {
 	return (make_href($EXTERNAL_UP_LINK, $icon),
		make_href($EXTERNAL_UP_LINK, "$EXTERNAL_UP_TITLE"))
	}
    elsif (($icon eq $previous_visible_mark
	    || $icon eq $previous_page_visible_mark)
	   && $EXTERNAL_PREV_LINK && $EXTERNAL_PREV_TITLE) {
	return (make_href($EXTERNAL_PREV_LINK, $icon),
		make_href($EXTERNAL_PREV_LINK, "$EXTERNAL_PREV_TITLE"))
	}
    elsif (($icon eq $next_visible_mark
	    ||  $icon eq $next_page_visible_mark)
	   && $EXTERNAL_DOWN_LINK && $EXTERNAL_DOWN_TITLE) {
	return (make_href($EXTERNAL_DOWN_LINK, $icon),
		make_href($EXTERNAL_DOWN_LINK, "$EXTERNAL_DOWN_TITLE"))
	}
    (&inactive_img($icon), "");
}

sub add_special_link {
    my($icon, $file, $current_file) = @_;
    (($file && ($file ne $current_file)) ? make_href($file, $icon) : undef)
}

sub img_tag {
    local($icon) = @_;
    my $alt;
    my $align = " align=bottom ";

    # having this list hardcoded here is really bogus....
    $alt = join('|', 'up', 'next_group', 'previous_group'
		, 'next', 'previous', 'change_begin_right', 'change_begin'
		, 'change_end_right', 'change_end', 'change_delete_right'
		, 'change_delete', 'contents', 'index', 'modules', 'blank');

    if ($icon =~ /(gif|png)$/) {
	$used_icons{$icon} = 1;
	if ($icon =~ /change_(begin|end|delete)_right/) { $align = ' ' };
	my $nav_border = "$NAV_BORDER";
	if ($icon =~ /($alt)/) {
	    $alt = $1;
	    $alt = ""
	      if ($alt eq "blank");
	}
	else {
	    $nav_border = '1';
	    $alt = '[*]';
	};
	if ($LOCAL_ICONS) {
	    return join('', '<img ', $iconsizes{$1}, $align
			,'border=', $nav_border, ' alt="', $alt
			,'" src="', $icon, '">' );
	}
	return join('', '<img ', $iconsizes{$1}, $align
		    ,'border=', $nav_border, ' alt="', $alt, "\"\n"
		    ,' src="', $ICONSERVER, "/$icon", '">' );
    }
    else {
	return $icon;
    }
}


sub do_cmd_arabic {
    # get rid of that nasty <SPAN CLASS="arabic">...</SPAN>
    local($ctr, $val, $id, $_) = &read_counter_value(@_[0]);
    return ($val ? &farabic($val) : "0") . $_;
}


sub gen_index_id {
    # this is used to ensure common index key generation and a stable sort
    my($str,$extra) = @_;
    sprintf('%s###%s%010d', $str, $extra, ++$global{'max_id'});
}

sub make_index_entry {
    my($br_id,$str) = @_;
    # If TITLE is not yet available (i.e the \index command is in the title of the
    # current section), use $ref_before.
    $TITLE = $ref_before unless $TITLE;
    # Save the reference
    $str = gen_index_id($str, '');
    $index{$str} .= make_half_href("$CURRENT_FILE#$br_id");
    "<a name=\"$br_id\">$anchor_invisible_mark<\/a>";
}


sub insert_index{
    my($mark,$datafile,$columns,$letters,$prefix) = @_;
    my $prog = "$myrootdir/tools/buildindex.py";
    my $index;
    if ($letters) {
	$index = `$prog --columns $columns --letters $datafile`;
    }
    else {
	$index = `$prog --columns $columns $datafile`;
    }
    s/$mark/$prefix$index/;
}

sub add_idx{
    print "\nBuilding HTML for the index ...";
    close(IDXFILE);
    insert_index($idx_mark, 'index.dat', $INDEX_COLUMNS, 1, '');
}


$idx_module_mark = '<tex2html_idx_module_mark>';
$idx_module_title = 'Module Index';

sub add_module_idx{
    print "\nBuilding HTML for the module index ...";
    my $key;
    my $first = 1;
    my $prevplat = '';
    my $allthesame = 1;
    my $prefix = '';
    foreach $key (keys %Modules) {
	$key =~ s/<tt>([a-zA-Z0-9._]*)<\/tt>/\1/;
	my $plat = "$ModulePlatforms{$key}";
	$plat = ''
	  if ($plat eq $IGNORE_PLATFORM_ANNOTATION);
	if (!$first) {
	    $allthesame = 0
	      if ($prevplat ne $plat);
	}
	else { $first = 0; }
	$prevplat = $plat;
    }
    open(MODIDXFILE, '>modindex.dat') || die "\n$!\n";
    foreach $key (keys %Modules) {
	# dump the line in the data file; just use a dummy seqno field
	my $nkey = $1;
	my $moditem = "$Modules{$key}";
	my $plat = '';
	$key =~ s/<tt>([a-zA-Z0-9._]*)<\/tt>/\1/;
	if ($ModulePlatforms{$key} && !$allthesame) {
	    $plat = " <em>($ModulePlatforms{$key})</em>";
	}
	print MODIDXFILE
	  $moditem
	    . $IDXFILE_FIELD_SEP
	    . "<tt class=module>$key</tt>$plat###\n";
    }
    close(MODIDXFILE);
    if (!$allthesame) {
	$prefix = <<PLAT_DISCUSS;


<p> Some module names are followed by an annotation indicating what
platform they are available on.</p>

PLAT_DISCUSS
    }
    insert_index($idx_module_mark, 'modindex.dat', $MODULE_INDEX_COLUMNS, 0,
		 $prefix);
}

# replace both indexes as needed:
sub add_idx_hook{
    add_idx() if (/$idx_mark/);
    add_module_idx() if (/$idx_module_mark/);
    process_python_state();
}


# In addition to the standard stuff, add label to allow named node files.
sub do_cmd_tableofcontents {
    local($_) = @_;
    $TITLE = $toc_title;
    $tocfile = $CURRENT_FILE;
    my($closures,$reopens) = preserve_open_tags();
    anchor_label('contents', $CURRENT_FILE, $_);	# this is added
    join('', "<BR>\n\\tableofchildlinks[off]", $closures
	 , make_section_heading($toc_title, 'H2'), $toc_mark
	 , $reopens, $_);
}
# In addition to the standard stuff, add label to allow named node files.
sub do_cmd_listoffigures {
    local($_) = @_;
    $TITLE = $lof_title;
    $loffile = $CURRENT_FILE;
    my($closures,$reopens) = preserve_open_tags();
    anchor_label('lof', $CURRENT_FILE, $_);		# this is added
    join('', "<BR>\n", $closures
	 , make_section_heading($lof_title, 'H2'), $lof_mark
	 , $reopens, $_);
}
# In addition to the standard stuff, add label to allow named node files.
sub do_cmd_listoftables {
    local($_) = @_;
    $TITLE = $lot_title;
    $lotfile = $CURRENT_FILE;
    my($closures,$reopens) = preserve_open_tags();
    anchor_label('lot', $CURRENT_FILE, $_);		# this is added
    join('', "<BR>\n", $closures
	 , make_section_heading($lot_title, 'H2'), $lot_mark
	 , $reopens, $_);
}
# In addition to the standard stuff, add label to allow named node files.
sub do_cmd_textohtmlinfopage {
    local($_) = @_;
    if ($INFO) {					# 
	anchor_label("about",$CURRENT_FILE,$_);		# this is added
    }							#
    my $the_version = '';				# and the rest is
    if ($t_date) {					# mostly ours
	$the_version = ",\n$t_date";
	if ($PYTHON_VERSION) {
	    $the_version .= ", Release $PYTHON_VERSION";
	}
    }
    $_ = (($INFO == 1)
      ? join('', $close_all
	, "<strong>$t_title</strong>$the_version\n"
	, `cat $myrootdir${dd}html${dd}about.dat`
	, $open_all, $_)
      : join('', $close_all, $INFO,"\n", $open_all, $_));
    $_;
}

# $idx_mark will be replaced with the real index at the end
sub do_cmd_textohtmlindex {
    local($_) = @_;
    $TITLE = $idx_title;
    $idxfile = $CURRENT_FILE;
    if (%index_labels) { make_index_labels(); }
    if (($SHORT_INDEX) && (%index_segment)) { make_preindex(); }
    else { $preindex = ''; }
    my $heading = make_section_heading($idx_title, 'h2') . $idx_mark;
    my($pre,$post) = minimize_open_tags($heading);
    anchor_label('genindex',$CURRENT_FILE,$_);		# this is added
    '<br>\n' . $pre . $_;
}

# $idx_module_mark will be replaced with the real index at the end
sub do_cmd_textohtmlmoduleindex {
    local($_) = @_;
    $TITLE = $idx_module_title;
    anchor_label("modindex",$CURRENT_FILE,$_);
    '<p>' . make_section_heading($idx_module_title, "h2")
      . $idx_module_mark . $_;
}

# The bibliography and the index should be treated as separate sections
# in their own HTML files. The \bibliography{} command acts as a sectioning command
# that has the desired effect. But when the bibliography is constructed 
# manually using the thebibliography environment, or when using the
# theindex environment it is not possible to use the normal sectioning 
# mechanism. This subroutine inserts a \bibliography{} or a dummy 
# \textohtmlindex command just before the appropriate environments
# to force sectioning.

# XXX	This *assumes* that if there are two {theindex} environments, the
#	first is the module index and the second is the standard index.  This
#	is sufficient for the current Python documentation, but that's about
#	it.

sub add_bbl_and_idx_dummy_commands {
    my $id = $global{'max_id'};

    s/([\\]begin\s*$O\d+$C\s*thebibliography)/$bbl_cnt++; $1/eg;
    s/([\\]begin\s*$O\d+$C\s*thebibliography)/$id++; "\\bibliography$O$id$C$O$id$C $1"/geo
      #if ($bbl_cnt == 1)
    ;
    #}
    #----------------------------------------------------------------------
    # (FLD) This was added
    my(@parts) = split(/\\begin\s*$O\d+$C\s*theindex/);
    if (scalar(@parts) == 3) {
	# Be careful to re-write the string in place, since $_ is *not*
	# returned explicity;  *** nasty side-effect dependency! ***
	print "\nadd_bbl_and_idx_dummy_commands ==> adding module index";
	my $rx = "([\\\\]begin\\s*$O\\d+$C\\s*theindex[\\s\\S]*)"
	         . "([\\\\]begin\\s*$O\\d+$C\\s*theindex)";
	s/$rx/\\textohtmlmoduleindex \1 \\textohtmlindex \2/o;
	# Add a button to the navigation areas:
	$CUSTOM_BUTTONS .= ("<a\n href=\"modindex.html\">"
			    . img_tag('modules.'.$IMAGE_TYPE) . "</a>");
    }
    else {
	$CUSTOM_BUTTONS .= img_tag('blank.' . $IMAGE_TYPE);
	$global{'max_id'} = $id; # not sure why....
	s/([\\]begin\s*$O\d+$C\s*theindex)/\\textohtmlindex $1/o;
	s/[\\]printindex/\\textohtmlindex /o;
    }
    #----------------------------------------------------------------------
    lib_add_bbl_and_idx_dummy_commands()
        if defined(&lib_add_bbl_and_idx_dummy_commands);
}

# The bibliographic references, the appendices, the lists of figures and tables
# etc. must appear in the contents table at the same level as the outermost
# sectioning command. This subroutine finds what is the outermost level and
# sets the above to the same level;

sub set_depth_levels {
    # Sets $outermost_level
    my $level;
    #RRM:  do not alter user-set value for  $MAX_SPLIT_DEPTH
    foreach $level ("part", "chapter", "section", "subsection",
		    "subsubsection", "paragraph") {
	last if (($outermost_level) = /\\($level)$delimiter_rx/);
    }
    $level = ($outermost_level ? $section_commands{$outermost_level} :
	      do {$outermost_level = 'section'; 3;});

    #RRM:  but calculate value for $MAX_SPLIT_DEPTH when a $REL_DEPTH was given
    if ($REL_DEPTH && $MAX_SPLIT_DEPTH) { 
	$MAX_SPLIT_DEPTH = $level + $MAX_SPLIT_DEPTH;
    } elsif (!($MAX_SPLIT_DEPTH)) { $MAX_SPLIT_DEPTH = 1 };

    %unnumbered_section_commands = ('tableofcontents' => $level,
				    'listoffigures' => $level,
				    'listoftables' => $level,
				    'bibliography' => $level,
				    'textohtmlindex' => $level,
				    'textohtmlmoduleindex' => $level);
    $section_headings{'textohtmlmoduleindex'} = 'h1';

    %section_commands = (%unnumbered_section_commands,
			 %section_commands);

    make_sections_rx();
}


# Fix from Ross Moore for ']' in \item[...]; this can be removed once the next
# patch to LaTeX2HTML is released and tested ... if the patch gets included.
# Be very careful to keep this around, just in case things break again!
#
sub protect_useritems {
    local(*_) = @_;
    local($preitems,$thisitem);
    while (/\\item\s*\[/) {
        $preitems .= $`;
	$_ = $';
        $thisitem = $&.'<<'.++$global{'max_id'}.'>>';
        s/^(((($O|$OP)\d+($C|$CP)).*\3|<[^<>]*>|[^\]<]+)*)\]/$thisitem.=$1;''/e;
        $preitems .= $thisitem . '<<' . $global{'max_id'} . '>>]';
	s/^]//;
    }
    $_ = $preitems . $_;
}

# This changes the markup used for {verbatim} environments, and is the
# best way I've found that ensures the <dl> goes on the outside of the
# <pre>...</pre>.
#
# Note that this *must* be done in the init file, not the python.perl
# style support file.  The %declarations must be set before initialize()
# is called in the main script.
#
%declarations = ('preform' => '<dl><dd><pre class=verbatim></pre></dl>',
		 %declarations);

1;	# This must be the last line

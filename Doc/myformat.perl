# myformat.perl by Guido van Rossum <guido@cwi.nl> 25 Jan 1994	-*- perl -*-
#
# Extension to LaTeX2HTML for documents using myformat.sty.
# Subroutines of the form do_cmd_<name> here define translations
# for LaTeX commands \<name> defined in the corresponding .sty file.
#
# XXX Not complete: \indexii etc.; \funcitem etc.

package main;

# \bcode and \ecode brackets around verbatim

sub do_cmd_bcode{ @_[0]; }
sub do_cmd_ecode{ @_[0]; }

# words typeset in a special way (not in HTML though)

sub do_cmd_ABC{ join('', 'ABC', @_[0]); }
sub do_cmd_UNIX{ join('', 'Unix', @_[0]); }
sub do_cmd_ASCII{ join('', 'ASCII', @_[0]); }
sub do_cmd_POSIX{ join('', 'POSIX', @_[0]); }
sub do_cmd_C{ join('', 'C', @_[0]); }
sub do_cmd_Cpp{ join('', 'C++', @_[0]); }
sub do_cmd_EOF{ join('', 'EOF', @_[0]); }
sub do_cmd_NULL{ join('', 'NULL', @_[0]); }

sub do_cmd_e{ local($_) = @_; '&#92;' . $_; }

sub do_cmd_optional{
	local($_) = @_;
	s/$any_next_pair_pr_rx/<\/var><big>\[<\/big><var>\2<\/var><big>\]<\/big><var>/;
	$_;
}

sub do_cmd_varvars{
	local($_) = @_;
	s/$any_next_pair_pr_rx/<var>\2<\/var>/;
	$_;
}

# texinfo-like formatting commands: \code{...} etc.

sub do_cmd_code{
	local($_) = @_;
	s/$any_next_pair_pr_rx/<code>\2<\/code>/;
	$_;
}

sub do_cmd_sectcode{ &do_cmd_code(@_); }
sub do_cmd_module{ &do_cmd_code(@_); }
sub do_cmd_keyword{ &do_cmd_code(@_); }
sub do_cmd_exception{ &do_cmd_code(@_); }
sub do_cmd_class{ &do_cmd_code(@_); }
sub do_cmd_function{ &do_cmd_code(@_); }
sub do_cmd_cfunction{ &do_cmd_code(@_); }
sub do_cmd_constant{ &do_cmd_code(@_); }
sub do_cmd_method{ &do_cmd_code(@_); }
sub do_cmd_email{ &do_cmd_code(@_); }

sub do_cmd_url{
    # use the URL as both text and hyperlink
    local($_) = @_;
    s/$any_next_pair_pr_rx/<code><a href="\2">\2<\/a><\/code>/;
    $_;
}

sub do_cmd_manpage{
    # two parameters:  \manpage{name}{section}
    local($_) = @_;
    local($any_next_pair_pr_rx3) = "$OP(\\d+)$CP([\\s\\S]*)$OP\\3$CP";
    s/$next_pair_pr_rx$any_next_pair_pr_rx3/<em>\2<\/em>(\4)/;
    $_;
}

sub do_cmd_kbd{
	local($_) = @_;
	s/$any_next_pair_pr_rx/<kbd>\2<\/kbd>/;
	$_;
}

sub do_cmd_key{
	local($_) = @_;
	s/$any_next_pair_pr_rx/<tt>\2<\/tt>/;
	$_;
}

sub do_cmd_var{
	local($_) = @_;
	s/$any_next_pair_pr_rx/<em>\2<\/em>/;
	$_;
}

sub do_cmd_dfn{
	local($_) = @_;
	s/$any_next_pair_pr_rx/<i><dfn>\2<\/dfn><\/i>/;
	$_;
}

sub do_cmd_emph{
	local($_) = @_;
	s/$any_next_pair_pr_rx/<em>\2<\/em>/;
	$_;
}

sub do_cmd_strong{
	local($_) = @_;
	s/$any_next_pair_pr_rx/<b>\2<\/b>/;
	$_;
}

# file and samp are at the end of this file since they screw up fontlock.

# index commands

sub do_cmd_indexii{
	local($_) = @_;
	s/$next_pair_pr_rx//o;
	local($br_id1, $str1) = ($1, $2);
	s/$next_pair_pr_rx//o;
	local($br_id2, $str2) = ($1, $2);
	join('', &make_index_entry($br_id1, "$str1 $str2"),
		 &make_index_entry($br_id2, "$str2, $str1"), $_);
}

sub do_cmd_indexiii{
	local($_) = @_;
	s/$next_pair_pr_rx//o;
	local($br_id1, $str1) = ($1, $2);
	s/$next_pair_pr_rx//o;
	local($br_id2, $str2) = ($1, $2);
	s/$next_pair_pr_rx//o;
	local($br_id3, $str3) = ($1, $2);
	join('', &make_index_entry($br_id1, "$str1 $str2 $str3"),
		 &make_index_entry($br_id2, "$str2 $str3, $str1"),
		 &make_index_entry($br_id3, "$str3, $str1 $str2"),
		 $_);
}

sub do_cmd_indexiv{
	local($_) = @_;
	s/$next_pair_pr_rx//o;
	local($br_id1, $str1) = ($1, $2);
	s/$next_pair_pr_rx//o;
	local($br_id2, $str2) = ($1, $2);
	s/$next_pair_pr_rx//o;
	local($br_id3, $str3) = ($1, $2);
	s/$next_pair_pr_rx//o;
	local($br_id4, $str4) = ($1, $2);
	join('', &make_index_entry($br_id1, "$str1 $str2 $str3 $str4"),
		 &make_index_entry($br_id2, "$str2 $str3 $str4, $str1"),
		 &make_index_entry($br_id3, "$str3 $str4, $str1 $str2"),
		 &make_index_entry($br_id4, "$str4, $str1 $str2 $str3"),
		 $_);
}

sub do_cmd_ttindex{
	&do_cmd_index(@_);
}

sub my_typed_index_helper{
	local($word, $_) = @_;
	s/$next_pair_pr_rx//o;
	local($br_id, $str) = ($1, $2);
	join('', &make_index_entry($br_id, "$str $word"),
		 &make_index_entry($br_id, "$word, $str"), $_);
}

sub do_cmd_stindex{ &my_typed_index_helper('statement', @_); }
sub do_cmd_opindex{ &my_typed_index_helper('operator', @_); }
sub do_cmd_exindex{ &my_typed_index_helper('exception', @_); }
sub do_cmd_obindex{ &my_typed_index_helper('object', @_); }

sub my_parword_index_helper{
	local($word, $_) = @_;
	s/$next_pair_pr_rx//o;
	local($br_id, $str) = ($1, $2);
	&make_index_entry($br_id, "$str ($word)") . $_;
}

sub make_mod_index_entry {
    local($br_id,$str,$define) = @_;
    local($halfref) = &make_half_href("$CURRENT_FILE#$br_id");
    # If TITLE is not yet available (i.e the \index command is in the title
    # of the current section), use $ref_before.
    $TITLE = $ref_before unless $TITLE;
    # Save the reference
    if ($define eq "DEF") {
	local($nstr,$garbage) = split / /, $str, 2;
	$Modules{$nstr} .= $halfref;
    }
    $str = &gen_index_id($str, $define);
    $index{$str} .= $halfref;
    "<a name=\"$br_id\">$anchor_invisible_mark<\/a>";
}

sub my_module_index_helper{
	local($word, $_, $define) = @_;
	s/$next_pair_pr_rx//o;
	local($br_id, $str) = ($1, $2);
	&make_mod_index_entry($br_id, "<tt>$str</tt> ($word module)",
			      $define) . $_;
}

sub do_cmd_bifuncindex{ &my_parword_index_helper('built-in function', @_); }
sub do_cmd_bimodindex{ &my_module_index_helper('built-in', @_, 'DEF'); }
sub do_cmd_stmodindex{ &my_module_index_helper('standard', @_, 'DEF'); }
sub do_cmd_bifuncindex{ &my_parword_index_helper('standard module', @_); }

sub do_cmd_refbimodindex{ &my_module_index_helper('built-in', @_, 'REF'); }
sub do_cmd_refstmodindex{ &my_module_index_helper('standard', @_, 'REF'); }

sub do_cmd_nodename{ &do_cmd_label(@_); }

sub init_myformat{
    # XXX need some way for this to be called after &initialise;
    # <<2>>...<<2>>
    $any_next_pair_rx3 = "$O(\\d+)$C([\\s\\S]*)$O\\3$C";
    $any_next_pair_rx5 = "$O(\\d+)$C([\\s\\S]*)$O\\5$C";
    $any_next_pair_rx7 = "$O(\\d+)$C([\\s\\S]*)$O\\7$C";
    $any_next_pair_rx9 = "$O(\\d+)$C([\\s\\S]*)$O\\9$C";
    # <#2#>...<#2#>
    $any_next_pair_pr_rx_3 = "$OP(\\d+)$CP([\\s\\S]*)$OP\\3$CP";
    $any_next_pair_pr_rx_5 = "$OP(\\d+)$CP([\\s\\S]*)$OP\\5$CP";
    $any_next_pair_pr_rx_7 = "$OP(\\d+)$CP([\\s\\S]*)$OP\\7$CP";
    $any_next_pair_pr_rx_9 = "$OP(\\d+)$CP([\\s\\S]*)$OP\\9$CP";
    $new_command{"indexsubitem"} = "";
}

&init_myformat;

sub get_indexsubitem{
  local($result) = $new_command{"indexsubitem"};
  #print "\nget_indexsubitem ==> $result\n";
  $result ? " $result" : '';
}

# similar to make_index_entry(), but includes the string in the result
# instead of the dummy filler.
#
sub make_str_index_entry {
    local($br_id,$str) = @_;
    # If TITLE is not yet available (i.e the \index command is in the title
    # of the current section), use $ref_before.
    $TITLE = $ref_before unless $TITLE;
    # Save the reference
    local($nstr) = &gen_index_id($str, '');
    $index{$nstr} .= &make_half_href("$CURRENT_FILE#$br_id");
    "<a name=\"$br_id\">$str<\/a>";
}

sub do_env_cfuncdesc{
  local($_) = @_;
  local($return_type,$function_name,$arg_list,$idx) = ('', '', '', '');
  local($cfuncdesc_rx) =
    "$next_pair_rx$any_next_pair_rx3$any_next_pair_rx5";
  $* = 1;
  if (/$cfuncdesc_rx/o) {
    $return_type = "$2";
    $function_name = "$4";
    $arg_list = "$6";
    $idx = &make_str_index_entry($3,
			"<tt>$function_name</tt>" . &get_indexsubitem);
  }
  $* = 0;
  "<dl><dt>$return_type <b>$idx</b>" .
    "(<var>$arg_list</var>)\n<dd>$'\n</dl>"
}

sub do_env_ctypedesc{
  local($_) = @_;
  local($type_name) = ('');
  local($cfuncdesc_rx) =
    "$next_pair_rx";
  $* = 1;
  if (/$cfuncdesc_rx/o) {
    $type_name = "$2";
    $idx = &make_str_index_entry($1,
				 "<tt>$type_name</tt>" . &get_indexsubitem);
  }
  $* = 0;
  "<dl><dt><b>$idx</b>\n<dd>$'\n</dl>"
}

sub do_env_cvardesc{
  local($_) = @_;
  local($var_type,$var_name,$idx) = ('', '', '');
  local($cfuncdesc_rx) = "$next_pair_rx$any_next_pair_rx3";
  $* = 1;
  if (/$cfuncdesc_rx/o) {
    $var_type = "$2";
    $var_name = "$4";
    $idx = &make_str_index_entry($3,"<tt>$var_name</tt>" . &get_indexsubitem);
  }
  $* = 0;
  "<dl><dt>$var_type <b>$idx</b>\n" .
    "<dd>$'\n</dl>";
}

sub do_env_funcdesc{
  local($_) = @_;
  local($function_name,$arg_list,$idx) = ('', '', '');
  local($funcdesc_rx) = "$next_pair_rx$any_next_pair_rx3";
  $* = 1;
  if (/$funcdesc_rx/o) {
    $function_name = "$2";
    $arg_list = "$4";
    $idx = &make_str_index_entry($3,
			"<tt>$function_name</tt>" . &get_indexsubitem);
  }
  $* = 0;
  "<dl><dt><b>$idx</b> (<var>$arg_list</var>)\n<dd>$'\n</dl>";
}

sub do_cmd_funcline{
  local($_) = @_;
  local($funcdesc_rx) = "$next_pair_pr_rx$OP(\\d+)$CP([\\s\\S]*)$OP\\3$CP";

  s/$funcdesc_rx//o;
  local($br_id, $function_name, $arg_list) = ($3, $2, $4);
  local($idx) = &make_str_index_entry($br_id, "<tt>$function_name</tt>");

  "<dt><b>$idx</b> (<var>$arg_list</var>)\n<dd>" . $_;
}

sub do_env_opcodedesc{
  local($_) = @_;
  local($opcode_name,$arg_list,$stuff,$idx) = ('', '', '', '');
  local($opcodedesc_rx) = "$next_pair_rx$any_next_pair_rx3";
  $* = 1;
  if (/$opcodedesc_rx/o) {
    $opcode_name = "$2";
    $arg_list = "$4";
    $idx = &make_str_index_entry($3,
			"<tt>$opcode_name</tt> (byte code instruction)");
  }
  $* = 0;
  $stuff = "<dl><dt><b>$idx</b>";
  if ($arg_list) {
    $stuff = "$stuff&nbsp;&nbsp;&nbsp;&nbsp;<var>$arg_list</var>";
  }
  $stuff . "\n<dd>$'\n</dl>";
}

sub do_env_datadesc{
  local($_) = @_;
  local($data_name,$idx) = ('', '');
  local($datadesc_rx) = "$next_pair_rx";
  $* = 1;
  if (/$datadesc_rx/o) {
    $data_name = "$2";
    $idx = &make_str_index_entry($3,
				 "<tt>$data_name</tt>" . &get_indexsubitem);
  }
  $* = 0;
  "<dl><dt><b>$idx</b>\n<dd>$'\n</dl>"
}

sub do_cmd_dataline{
  local($_) = @_;

  s/$next_pair_pr_rx//o;
  local($br_id, $data_name) = ($1, $2);
  local($idx) = &make_str_index_entry($br_id, "<tt>$data_name</tt>");

  "<dt><b>$idx</b>\n<dd>" . $_;
}

sub do_env_excdesc{ &do_env_datadesc(@_); }

@col_aligns = ("<td>", "<td>", "<td>");

sub setup_column_alignments{
  local($_) = @_;
  local($j1,$a1,$a2,$a3,$j4) = split(/[|]/,$_);
  local($th1,$th2,$th3) = ('<th>', '<th>', '<th>');
  $col_aligns[0] = (($a1 eq "c") ? "<td align=center>" : "<td>");
  $col_aligns[1] = (($a2 eq "c") ? "<td align=center>" : "<td>");
  $col_aligns[2] = (($a3 eq "c") ? "<td align=center>" : "<td>");
  # return the aligned header start tags; only used for \begin{tableiii?}
  $th1 = (($a1 eq "l") ? "<th align=left>"
	  : ($a1 eq "r" ? "<th align=right>" : "<th>"));
  $th2 = (($a2 eq "l") ? "<th align=left>"
	  : ($a2 eq "r" ? "<th align=right>" : "<th>"));
  $th3 = (($a3 eq "l") ? "<th align=left>"
	  : ($a3 eq "r" ? "<th align=right>" : "<th>"));
  ($th1, $th2, $th3);
}

sub do_env_tableii{
  local($_) = @_;
  local($font,$h1,$h2) = ('', '', '');
  local($tableiii_rx) =
    "$next_pair_rx$any_next_pair_rx3$any_next_pair_rx5$any_next_pair_rx7";
  $* = 1;
  if (/$tableiii_rx/o) {
    $font = $4;
    $h1 = $6;
    $h2 = $8;
  }
  local($th1,$th2,$th3) = &setup_column_alignments($2);
  $globals{"lineifont"} = $font;
  "<table border align=center>\n  <tr>$th1$h1</th>\n      $th2$h2</th>$'\n"
    . "</table>";
}

sub do_cmd_lineii{
  local($_) = @_;
  s/$next_pair_pr_rx//o;
  local($c1) = $2;
  s/$next_pair_pr_rx//o;
  local($c2) = $2;
  local($font) = $globals{"lineifont"};
  local($c1align, $c2align) = @col_aligns[0,1];
  "<tr>$c1align<$font>$c1</$font></td>\n"
    . "      $c2align$c2</td>$'";
}

sub do_env_tableiii{
  local($_) = @_;
  local($font,$h1,$h2,$h3) = ('', '', '', '');
  
  local($tableiii_rx) =
    "$next_pair_rx$any_next_pair_rx3$any_next_pair_rx5$any_next_pair_rx7"
      . "$any_next_pair_rx9";
  $* = 1;
  if (/$tableiii_rx/o) {
    $font = $4;
    $h1 = $6;
    $h2 = $8;
    $h3 = $10;
  }
  local($th1,$th2,$th3) = &setup_column_alignments($2);
  $globals{"lineifont"} = $font;
  "<table border align=center>\n  <tr>$th1$h1</th>\n      $th2$h2</th>"
    . "\n      $th3$h3</th>$'\n"
    . "</table>";
}

sub do_cmd_lineiii{
  local($_) = @_;
  s/$next_pair_pr_rx//o;
  local($c1) = $2;
  s/$next_pair_pr_rx//o;
  local($c2) = $2;
  s/$next_pair_pr_rx//o;
  local($c3) = $2;
  local($font) = $globals{"lineifont"};
  local($c1align, $c2align, $c3align) = @col_aligns;
  "<tr>$c1align<$font>$c1</$font></td>\n"
    . "      $c2align$c2</td>\n"
    . "      $c3align$c3</td>$'";
}

sub do_env_seealso{
  "<p><b>See Also:</b></p>\n" . @_[0];
}

sub do_cmd_seemodule{
  local($_) = @_;
  local($any_next_pair_pr_rx3) = "$OP(\\d+)$CP([\\s\\S]*)$OP\\3$CP";
  s/$next_pair_pr_rx$any_next_pair_pr_rx3/<p><code><b>\2<\/b><\/code> (\4)<\/p>/;
  $_;
}

sub do_cmd_seetext{
  "<p>" . @_[0];
}

# These are located down here since they screw up fontlock.

sub do_cmd_file{
	local($_) = @_;
	s/$any_next_pair_pr_rx/`<code>\2<\/code>'/;
	$_;
}

sub do_cmd_samp{
	local($_) = @_;
	s/$any_next_pair_pr_rx/`<samp>\2<\/samp>'/;
	$_;
}

1;				# This must be the last line

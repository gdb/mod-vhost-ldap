"""Suite Type Definitions: Definitions of records used in scripting the Finder
Level 1, version 1

Generated from /System/Library/CoreServices/Finder.app
AETE/AEUT resource version 0/144, language 0, script 0
"""

import aetools
import MacOS

_code = 'tpdf'

class Type_Definitions_Events:

	pass


class alias_list(aetools.ComponentItem):
	"""alias list - A list of aliases.  Use \xd4as alias list\xd5 when a list of aliases is needed (instead of a list of file system item references). """
	want = 'alst'

class column(aetools.ComponentItem):
	"""column - a column of a list view """
	want = 'lvcl'
class index(aetools.NProperty):
	"""index - the index in the front-to-back ordering within its container """
	which = 'pidx'
	want = 'long'
class name(aetools.NProperty):
	"""name - the column name """
	which = 'pnam'
	want = 'elsv'
class sort_direction(aetools.NProperty):
	"""sort direction - The direction in which the window is sorted """
	which = 'sord'
	want = 'sodr'
class visible(aetools.NProperty):
	"""visible - is this column visible """
	which = 'pvis'
	want = 'bool'
class width(aetools.NProperty):
	"""width - the width of this column """
	which = 'clwd'
	want = 'shor'

columns = column

class icon_family(aetools.ComponentItem):
	"""icon family - (NOT AVAILABLE YET) A family of icons """
	want = 'ifam'
class large_32_bit_icon(aetools.NProperty):
	"""large 32 bit icon - the large 32-bit color icon """
	which = 'il32'
	want = 'il32'
class large_4_bit_icon(aetools.NProperty):
	"""large 4 bit icon - the large 4-bit color icon """
	which = 'icl4'
	want = 'icl4'
class large_8_bit_icon(aetools.NProperty):
	"""large 8 bit icon - the large 8-bit color icon """
	which = 'icl8'
	want = 'icl8'
class large_8_bit_mask(aetools.NProperty):
	"""large 8 bit mask - the large 8-bit mask for large 32-bit icons """
	which = 'l8mk'
	want = 'l8mk'
class large_monochrome_icon_and_mask(aetools.NProperty):
	"""large monochrome icon and mask - the large black-and-white icon and the mask for large icons """
	which = 'ICN#'
	want = 'ICN#'
class small_32_bit_icon(aetools.NProperty):
	"""small 32 bit icon - the small 32-bit color icon """
	which = 'is32'
	want = 'is32'
class small_4_bit_icon(aetools.NProperty):
	"""small 4 bit icon - the small 4-bit color icon """
	which = 'ics4'
	want = 'ics4'
class small_8_bit_icon(aetools.NProperty):
	"""small 8 bit icon - the small 8-bit color icon """
	which = 'ics8'
	want = 'ics8'

small_8_bit_mask = small_8_bit_icon
class small_monochrome_icon_and_mask(aetools.NProperty):
	"""small monochrome icon and mask - the small black-and-white icon and the mask for small icons """
	which = 'ics#'
	want = 'ics#'

class icon_view_options(aetools.ComponentItem):
	"""icon view options - the icon view options """
	want = 'icop'
class arrangement(aetools.NProperty):
	"""arrangement - the property by which to keep icons arranged """
	which = 'iarr'
	want = 'earr'
class icon_size(aetools.NProperty):
	"""icon size - the size of icons displayed in the icon view """
	which = 'lvis'
	want = 'shor'

class label(aetools.ComponentItem):
	"""label - (NOT AVAILABLE YET) A Finder label (name and color) """
	want = 'clbl'
class color(aetools.NProperty):
	"""color - the color associated with the label """
	which = 'colr'
	want = 'cRGB'

class list_view_options(aetools.ComponentItem):
	"""list view options - the list view options """
	want = 'lvop'
class calculates_folder_sizes(aetools.NProperty):
	"""calculates folder sizes - Are folder sizes calculated and displayed in the window? """
	which = 'sfsz'
	want = 'bool'
class sort_column(aetools.NProperty):
	"""sort column - the column that the list view is sorted on """
	which = 'srtc'
	want = 'lvcl'
class uses_relative_dates(aetools.NProperty):
	"""uses relative dates - Are relative dates (e.g., today, yesterday) shown in the list view? """
	which = 'urdt'
	want = 'bool'
#        element 'lvcl' as ['indx', 'rele', 'rang', 'test']

class preferences(aetools.ComponentItem):
	"""preferences - (NOT AVAILABLE, SUBJECT TO CHANGE) The Finder Preferences """
	want = 'cprf'
class button_view_arrangement(aetools.NProperty):
	"""button view arrangement - the method of arrangement of icons in default Finder button view windows """
	which = 'barr'
	want = 'earr'
class button_view_icon_size(aetools.NProperty):
	"""button view icon size - the size of icons displayed in Finder button view windows. """
	which = 'bisz'
	want = 'long'
class delay_before_springing(aetools.NProperty):
	"""delay before springing - the delay before springing open a container in ticks (1/60th of a second) (12 is shortest delay, 60 is longest delay) """
	which = 'dela'
	want = 'shor'
class list_view_icon_size(aetools.NProperty):
	"""list view icon size - the size of icons displayed in Finder list view windows. """
	which = 'lisz'
	want = 'long'
class shows_comments(aetools.NProperty):
	"""shows comments - Are comments displayed in default Finder list view windows? """
	which = 'scom'
	want = 'bool'
class shows_creation_date(aetools.NProperty):
	"""shows creation date - Are creation dates displayed in default Finder list view windows? """
	which = 'scda'
	want = 'bool'
class shows_kind(aetools.NProperty):
	"""shows kind - Are document kinds displayed in default Finder list view windows? """
	which = 'sknd'
	want = 'bool'
class shows_label(aetools.NProperty):
	"""shows label - Are labels displayed in default Finder list view windows? """
	which = 'slbl'
	want = 'bool'
class shows_modification_date(aetools.NProperty):
	"""shows modification date - Are modification dates displayed in default Finder list view windows? """
	which = 'sdat'
	want = 'bool'
class shows_size(aetools.NProperty):
	"""shows size - Are file sizes displayed in default Finder list view windows? """
	which = 'ssiz'
	want = 'bool'
class shows_version(aetools.NProperty):
	"""shows version - Are file versions displayed in default Finder list view windows? """
	which = 'svrs'
	want = 'bool'

spatial_view_arrangement = arrangement
class spatial_view_icon_size(aetools.NProperty):
	"""spatial view icon size - the size of icons displayed in Finder spatial view windows. """
	which = 'iisz'
	want = 'long'
class spring_open_folders(aetools.NProperty):
	"""spring open folders - Spring open folders after the specified delay? """
	which = 'sprg'
	want = 'bool'
class uses_simple_menus(aetools.NProperty):
	"""uses simple menus - Use simplified Finder menus? """
	which = 'usme'
	want = 'bool'
class uses_wide_grid(aetools.NProperty):
	"""uses wide grid - Space icons on a wide grid? """
	which = 'uswg'
	want = 'bool'
class view_font(aetools.NProperty):
	"""view font - the id of the font used in Finder views. """
	which = 'vfnt'
	want = 'long'
class view_font_size(aetools.NProperty):
	"""view font size - the size of the font used in Finder views """
	which = 'vfsz'
	want = 'long'
class window(aetools.NProperty):
	"""window - the window that would open if Finder preferences was opened """
	which = 'cwin'
	want = 'pwnd'
#        element 'clbl' as ['indx', 'name']
alias_list._superclassnames = []
alias_list._privpropdict = {
}
alias_list._privelemdict = {
}
column._superclassnames = []
column._privpropdict = {
	'index' : index,
	'name' : name,
	'sort_direction' : sort_direction,
	'visible' : visible,
	'width' : width,
}
column._privelemdict = {
}
icon_family._superclassnames = []
icon_family._privpropdict = {
	'large_32_bit_icon' : large_32_bit_icon,
	'large_4_bit_icon' : large_4_bit_icon,
	'large_8_bit_icon' : large_8_bit_icon,
	'large_8_bit_mask' : large_8_bit_mask,
	'large_monochrome_icon_and_mask' : large_monochrome_icon_and_mask,
	'small_32_bit_icon' : small_32_bit_icon,
	'small_4_bit_icon' : small_4_bit_icon,
	'small_8_bit_icon' : small_8_bit_icon,
	'small_8_bit_mask' : small_8_bit_mask,
	'small_monochrome_icon_and_mask' : small_monochrome_icon_and_mask,
}
icon_family._privelemdict = {
}
icon_view_options._superclassnames = []
icon_view_options._privpropdict = {
	'arrangement' : arrangement,
	'icon_size' : icon_size,
}
icon_view_options._privelemdict = {
}
label._superclassnames = []
label._privpropdict = {
	'color' : color,
	'index' : index,
	'name' : name,
}
label._privelemdict = {
}
list_view_options._superclassnames = []
list_view_options._privpropdict = {
	'calculates_folder_sizes' : calculates_folder_sizes,
	'icon_size' : icon_size,
	'sort_column' : sort_column,
	'uses_relative_dates' : uses_relative_dates,
}
list_view_options._privelemdict = {
	'column' : column,
}
preferences._superclassnames = []
preferences._privpropdict = {
	'button_view_arrangement' : button_view_arrangement,
	'button_view_icon_size' : button_view_icon_size,
	'calculates_folder_sizes' : calculates_folder_sizes,
	'delay_before_springing' : delay_before_springing,
	'list_view_icon_size' : list_view_icon_size,
	'shows_comments' : shows_comments,
	'shows_creation_date' : shows_creation_date,
	'shows_kind' : shows_kind,
	'shows_label' : shows_label,
	'shows_modification_date' : shows_modification_date,
	'shows_size' : shows_size,
	'shows_version' : shows_version,
	'spatial_view_arrangement' : spatial_view_arrangement,
	'spatial_view_icon_size' : spatial_view_icon_size,
	'spring_open_folders' : spring_open_folders,
	'uses_relative_dates' : uses_relative_dates,
	'uses_simple_menus' : uses_simple_menus,
	'uses_wide_grid' : uses_wide_grid,
	'view_font' : view_font,
	'view_font_size' : view_font_size,
	'window' : window,
}
preferences._privelemdict = {
	'label' : label,
}

#
# Indices of types declared in this module
#
_classdeclarations = {
	'alst' : alias_list,
	'clbl' : label,
	'cprf' : preferences,
	'icop' : icon_view_options,
	'ifam' : icon_family,
	'lvcl' : column,
	'lvop' : list_view_options,
}

_propdeclarations = {
	'ICN#' : large_monochrome_icon_and_mask,
	'barr' : button_view_arrangement,
	'bisz' : button_view_icon_size,
	'clwd' : width,
	'colr' : color,
	'cwin' : window,
	'dela' : delay_before_springing,
	'iarr' : arrangement,
	'icl4' : large_4_bit_icon,
	'icl8' : large_8_bit_icon,
	'ics#' : small_monochrome_icon_and_mask,
	'ics4' : small_4_bit_icon,
	'ics8' : small_8_bit_icon,
	'iisz' : spatial_view_icon_size,
	'il32' : large_32_bit_icon,
	'is32' : small_32_bit_icon,
	'l8mk' : large_8_bit_mask,
	'lisz' : list_view_icon_size,
	'lvis' : icon_size,
	'pidx' : index,
	'pnam' : name,
	'pvis' : visible,
	'scda' : shows_creation_date,
	'scom' : shows_comments,
	'sdat' : shows_modification_date,
	'sfsz' : calculates_folder_sizes,
	'sknd' : shows_kind,
	'slbl' : shows_label,
	'sord' : sort_direction,
	'sprg' : spring_open_folders,
	'srtc' : sort_column,
	'ssiz' : shows_size,
	'svrs' : shows_version,
	'urdt' : uses_relative_dates,
	'usme' : uses_simple_menus,
	'uswg' : uses_wide_grid,
	'vfnt' : view_font,
	'vfsz' : view_font_size,
}

_compdeclarations = {
}

_enumdeclarations = {
}

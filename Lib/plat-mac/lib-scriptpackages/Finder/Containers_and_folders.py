"""Suite Containers and folders: Classes that can contain other file system items
Level 1, version 1

Generated from /Volumes/Moes/Systeemmap/Finder
AETE/AEUT resource version 0/144, language 0, script 0
"""

import aetools
import MacOS

_code = 'fndr'

class Containers_and_folders_Events:

	pass


class container(aetools.ComponentItem):
	"""container - An item that contains other items """
	want = 'ctnr'
class _3c_Inheritance_3e_(aetools.NProperty):
	"""<Inheritance> - inherits some of its properties from the item class """
	which = 'c@#^'
	want = 'cobj'
class completely_expanded(aetools.NProperty):
	"""completely expanded - Are the container and all of its children opened as outlines? (can only be set for containers viewed as lists) """
	which = 'pexc'
	want = 'bool'
class entire_contents(aetools.NProperty):
	"""entire contents - the entire contents of the container, including the contents of its children """
	which = 'ects'
	want = 'obj '
class expandable(aetools.NProperty):
	"""expandable - Is the container capable of being expanded as an outline? """
	which = 'pexa'
	want = 'bool'
class expanded(aetools.NProperty):
	"""expanded - Is the container opened as an outline? (can only be set for containers viewed as lists) """
	which = 'pexp'
	want = 'bool'
class icon_size(aetools.NProperty):
	"""icon size - ... alternatively, you can specify the icons size as a constant """
	which = 'lvis'
	want = 'isiz'
class selection(aetools.NProperty):
	"""selection - the selection visible to the user """
	which = 'sele'
	want = 'obj '
class view_options_window(aetools.NProperty):
	"""view options window - the view options window for the container (can only be opened when the container window is open) """
	which = 'vwnd'
	want = 'vwnd'
#        element 'alia' as ['indx', 'name']
#        element 'appf' as ['indx', 'name', 'ID  ']
#        element 'cfol' as ['indx', 'name', 'ID  ']
#        element 'clpf' as ['indx', 'name']
#        element 'cobj' as ['indx', 'name']
#        element 'ctnr' as ['indx', 'name']
#        element 'dafi' as ['indx', 'name']
#        element 'docf' as ['indx', 'name']
#        element 'dsut' as ['indx', 'name']
#        element 'file' as ['indx', 'name']
#        element 'fntf' as ['indx', 'name']
#        element 'fsut' as ['indx', 'name']
#        element 'inlf' as ['indx', 'name']
#        element 'pack' as ['indx', 'name']
#        element 'sctr' as ['indx', 'name']
#        element 'sndf' as ['indx', 'name']
#        element 'stcs' as ['indx', 'name']

containers = container

class desktop_2d_object(aetools.ComponentItem):
	"""desktop-object - Desktop-object is the class of the \xd2desktop\xd3 object """
	want = 'cdsk'
class startup_disk(aetools.NProperty):
	"""startup disk - the startup disk """
	which = 'sdsk'
	want = 'cdis'
class trash(aetools.NProperty):
	"""trash - the trash """
	which = 'trsh'
	want = 'ctrs'
#        element 'alia' as ['indx', 'name']
#        element 'appf' as ['indx', 'name', 'ID  ']
#        element 'cdis' as ['indx', 'name']
#        element 'cfol' as ['indx', 'name', 'ID  ']
#        element 'clpf' as ['indx', 'name']
#        element 'cobj' as ['indx', 'name']
#        element 'ctnr' as ['indx', 'name']
#        element 'dafi' as ['indx', 'name']
#        element 'docf' as ['indx', 'name']
#        element 'dsut' as ['indx', 'name']
#        element 'file' as ['indx', 'name']
#        element 'fntf' as ['indx', 'name']
#        element 'fsut' as ['indx', 'name']
#        element 'inlf' as ['indx', 'name']
#        element 'pack' as ['indx', 'name']
#        element 'sctr' as ['indx', 'name']
#        element 'sndf' as ['indx', 'name']
#        element 'stcs' as ['indx', 'name']

class disk(aetools.ComponentItem):
	"""disk - A disk """
	want = 'cdis'
class capacity(aetools.NProperty):
	"""capacity - the total number of bytes (free or used) on the disk """
	which = 'capa'
	want = 'long'
class ejectable(aetools.NProperty):
	"""ejectable - Can the media be ejected (floppies, CD's, and so on)? """
	which = 'isej'
	want = 'bool'
class free_space(aetools.NProperty):
	"""free space - the number of free bytes left on the disk """
	which = 'frsp'
	want = 'long'
class local_volume(aetools.NProperty):
	"""local volume - Is the media a local volume (as opposed to a file server)? """
	which = 'isrv'
	want = 'bool'
class startup(aetools.NProperty):
	"""startup - Is this disk the boot disk? """
	which = 'istd'
	want = 'bool'
#        element 'alia' as ['indx', 'name']
#        element 'appf' as ['indx', 'name', 'ID  ']
#        element 'cfol' as ['indx', 'name', 'ID  ']
#        element 'clpf' as ['indx', 'name']
#        element 'cobj' as ['indx', 'name']
#        element 'ctnr' as ['indx', 'name']
#        element 'dafi' as ['indx', 'name']
#        element 'docf' as ['indx', 'name']
#        element 'dsut' as ['indx', 'name']
#        element 'file' as ['indx', 'name']
#        element 'fntf' as ['indx', 'name']
#        element 'fsut' as ['indx', 'name']
#        element 'inlf' as ['indx', 'name']
#        element 'pack' as ['indx', 'name']
#        element 'sctr' as ['indx', 'name']
#        element 'sndf' as ['indx', 'name']
#        element 'stcs' as ['indx', 'name']

disks = disk

class folder(aetools.ComponentItem):
	"""folder - A folder """
	want = 'cfol'
#        element 'alia' as ['indx', 'name']
#        element 'appf' as ['indx', 'name', 'ID  ']
#        element 'cfol' as ['indx', 'name', 'ID  ']
#        element 'clpf' as ['indx', 'name']
#        element 'cobj' as ['indx', 'name']
#        element 'ctnr' as ['indx', 'name']
#        element 'dafi' as ['indx', 'name']
#        element 'docf' as ['indx', 'name']
#        element 'dsut' as ['indx', 'name']
#        element 'file' as ['indx', 'name']
#        element 'fntf' as ['indx', 'name']
#        element 'fsut' as ['indx', 'name']
#        element 'inlf' as ['indx', 'name']
#        element 'pack' as ['indx', 'name']
#        element 'sctr' as ['indx', 'name']
#        element 'sndf' as ['indx', 'name']
#        element 'stcs' as ['indx', 'name']

folders = folder

class sharable_container(aetools.ComponentItem):
	"""sharable container - A container that may be shared (disks and folders) """
	want = 'sctr'
class exported(aetools.NProperty):
	"""exported - Is the container a share point or inside a share point, i.e., can the container be shared? (file sharing must be on to use this property) """
	which = 'sexp'
	want = 'bool'
class group(aetools.NProperty):
	"""group - the user or group that has special access to the container (file sharing must be on to use this property) """
	which = 'sgrp'
	want = 'itxt'
class group_privileges(aetools.NProperty):
	"""group privileges - the see folders/see files/make changes privileges for the group (file sharing must be on to use this property) """
	which = 'gppr'
	want = 'priv'
class guest_privileges(aetools.NProperty):
	"""guest privileges - the see folders/see files/make changes privileges for everyone (file sharing must be on to use this property) """
	which = 'gstp'
	want = 'priv'
class mounted(aetools.NProperty):
	"""mounted - Is the container mounted on another machine's desktop? (file sharing must be on to use this property) """
	which = 'smou'
	want = 'bool'
class owner(aetools.NProperty):
	"""owner - the user that owns the container (file sharing must be on to use this property) """
	which = 'sown'
	want = 'itxt'
class owner_privileges(aetools.NProperty):
	"""owner privileges - the see folders/see files/make changes privileges for the owner (file sharing must be on to use this property) """
	which = 'ownr'
	want = 'priv'
class privileges_inherited(aetools.NProperty):
	"""privileges inherited - Are the privileges of the container always the same as the container in which it is stored? (file sharing must be on to use this property) """
	which = 'iprv'
	want = 'bool'
class protected(aetools.NProperty):
	"""protected - Is the container protected from being moved, renamed and deleted? (file sharing must be on to use this property) """
	which = 'spro'
	want = 'bool'
class shared(aetools.NProperty):
	"""shared - Is the container a share point, i.e., is the container currently being shared? (file sharing must be on to use this property) """
	which = 'shar'
	want = 'bool'
#        element 'alia' as ['indx', 'name']
#        element 'appf' as ['indx', 'name', 'ID  ']
#        element 'cfol' as ['indx', 'name', 'ID  ']
#        element 'clpf' as ['indx', 'name']
#        element 'cobj' as ['indx', 'name']
#        element 'ctnr' as ['indx', 'name']
#        element 'dafi' as ['indx', 'name']
#        element 'docf' as ['indx', 'name']
#        element 'dsut' as ['indx', 'name']
#        element 'file' as ['indx', 'name']
#        element 'fntf' as ['indx', 'name']
#        element 'fsut' as ['indx', 'name']
#        element 'inlf' as ['indx', 'name']
#        element 'pack' as ['indx', 'name']
#        element 'sctr' as ['indx', 'name']
#        element 'sndf' as ['indx', 'name']
#        element 'stcs' as ['indx', 'name']

sharable_containers = sharable_container

class sharing_privileges(aetools.ComponentItem):
	"""sharing privileges - A set of sharing properties (used in sharable containers) """
	want = 'priv'
class make_changes(aetools.NProperty):
	"""make changes - Can changes be made? """
	which = 'prvw'
	want = 'bool'
class see_files(aetools.NProperty):
	"""see files - Can files be seen? """
	which = 'prvr'
	want = 'bool'
class see_folders(aetools.NProperty):
	"""see folders - Can folders be seen? """
	which = 'prvs'
	want = 'bool'

class trash_2d_object(aetools.ComponentItem):
	"""trash-object - Trash-object is the class of the \xd2trash\xd3 object """
	want = 'ctrs'
class warns_before_emptying(aetools.NProperty):
	"""warns before emptying - Display a dialog when emptying the trash? """
	which = 'warn'
	want = 'bool'
#        element 'alia' as ['indx', 'name']
#        element 'appf' as ['indx', 'name', 'ID  ']
#        element 'cfol' as ['indx', 'name', 'ID  ']
#        element 'clpf' as ['indx', 'name']
#        element 'cobj' as ['indx', 'name']
#        element 'ctnr' as ['indx', 'name']
#        element 'dafi' as ['indx', 'name']
#        element 'docf' as ['indx', 'name']
#        element 'dsut' as ['indx', 'name']
#        element 'file' as ['indx', 'name']
#        element 'fntf' as ['indx', 'name']
#        element 'fsut' as ['indx', 'name']
#        element 'inlf' as ['indx', 'name']
#        element 'pack' as ['indx', 'name']
#        element 'sctr' as ['indx', 'name']
#        element 'sndf' as ['indx', 'name']
#        element 'stcs' as ['indx', 'name']
import Earlier_terms
container._superclassnames = ['item']
import Files_and_suitcases
container._privpropdict = {
	'_3c_Inheritance_3e_' : _3c_Inheritance_3e_,
	'completely_expanded' : completely_expanded,
	'entire_contents' : entire_contents,
	'expandable' : expandable,
	'expanded' : expanded,
	'icon_size' : icon_size,
	'icon_size' : icon_size,
	'selection' : selection,
	'view_options_window' : view_options_window,
}
container._privelemdict = {
	'accessory_suitcase' : Earlier_terms.accessory_suitcase,
	'alias_file' : Files_and_suitcases.alias_file,
	'application_file' : Earlier_terms.application_file,
	'clipping' : Files_and_suitcases.clipping,
	'container' : container,
	'desk_accessory_file' : Files_and_suitcases.desk_accessory_file,
	'document_file' : Files_and_suitcases.document_file,
	'file' : Files_and_suitcases.file,
	'folder' : folder,
	'font_file' : Files_and_suitcases.font_file,
	'font_suitcase' : Files_and_suitcases.font_suitcase,
	'internet_location' : Earlier_terms.internet_location,
	'item' : Earlier_terms.item,
	'package' : Files_and_suitcases.package,
	'sharable_container' : sharable_container,
	'sound_file' : Files_and_suitcases.sound_file,
	'suitcase' : Files_and_suitcases.suitcase,
}
desktop_2d_object._superclassnames = ['container']
desktop_2d_object._privpropdict = {
	'_3c_Inheritance_3e_' : _3c_Inheritance_3e_,
	'startup_disk' : startup_disk,
	'trash' : trash,
}
desktop_2d_object._privelemdict = {
	'accessory_suitcase' : Earlier_terms.accessory_suitcase,
	'alias_file' : Files_and_suitcases.alias_file,
	'application_file' : Earlier_terms.application_file,
	'clipping' : Files_and_suitcases.clipping,
	'container' : container,
	'desk_accessory_file' : Files_and_suitcases.desk_accessory_file,
	'disk' : disk,
	'document_file' : Files_and_suitcases.document_file,
	'file' : Files_and_suitcases.file,
	'folder' : folder,
	'font_file' : Files_and_suitcases.font_file,
	'font_suitcase' : Files_and_suitcases.font_suitcase,
	'internet_location' : Earlier_terms.internet_location,
	'item' : Earlier_terms.item,
	'package' : Files_and_suitcases.package,
	'sharable_container' : sharable_container,
	'sound_file' : Files_and_suitcases.sound_file,
	'suitcase' : Files_and_suitcases.suitcase,
}
disk._superclassnames = ['sharable_container']
disk._privpropdict = {
	'_3c_Inheritance_3e_' : _3c_Inheritance_3e_,
	'capacity' : capacity,
	'ejectable' : ejectable,
	'free_space' : free_space,
	'local_volume' : local_volume,
	'startup' : startup,
}
disk._privelemdict = {
	'accessory_suitcase' : Earlier_terms.accessory_suitcase,
	'alias_file' : Files_and_suitcases.alias_file,
	'application_file' : Earlier_terms.application_file,
	'clipping' : Files_and_suitcases.clipping,
	'container' : container,
	'desk_accessory_file' : Files_and_suitcases.desk_accessory_file,
	'document_file' : Files_and_suitcases.document_file,
	'file' : Files_and_suitcases.file,
	'folder' : folder,
	'font_file' : Files_and_suitcases.font_file,
	'font_suitcase' : Files_and_suitcases.font_suitcase,
	'internet_location' : Earlier_terms.internet_location,
	'item' : Earlier_terms.item,
	'package' : Files_and_suitcases.package,
	'sharable_container' : sharable_container,
	'sound_file' : Files_and_suitcases.sound_file,
	'suitcase' : Files_and_suitcases.suitcase,
}
folder._superclassnames = ['sharable_container']
folder._privpropdict = {
	'_3c_Inheritance_3e_' : _3c_Inheritance_3e_,
}
folder._privelemdict = {
	'accessory_suitcase' : Earlier_terms.accessory_suitcase,
	'alias_file' : Files_and_suitcases.alias_file,
	'application_file' : Earlier_terms.application_file,
	'clipping' : Files_and_suitcases.clipping,
	'container' : container,
	'desk_accessory_file' : Files_and_suitcases.desk_accessory_file,
	'document_file' : Files_and_suitcases.document_file,
	'file' : Files_and_suitcases.file,
	'folder' : folder,
	'font_file' : Files_and_suitcases.font_file,
	'font_suitcase' : Files_and_suitcases.font_suitcase,
	'internet_location' : Earlier_terms.internet_location,
	'item' : Earlier_terms.item,
	'package' : Files_and_suitcases.package,
	'sharable_container' : sharable_container,
	'sound_file' : Files_and_suitcases.sound_file,
	'suitcase' : Files_and_suitcases.suitcase,
}
sharable_container._superclassnames = ['container']
sharable_container._privpropdict = {
	'_3c_Inheritance_3e_' : _3c_Inheritance_3e_,
	'exported' : exported,
	'group' : group,
	'group_privileges' : group_privileges,
	'guest_privileges' : guest_privileges,
	'mounted' : mounted,
	'owner' : owner,
	'owner_privileges' : owner_privileges,
	'privileges_inherited' : privileges_inherited,
	'protected' : protected,
	'shared' : shared,
}
sharable_container._privelemdict = {
	'accessory_suitcase' : Earlier_terms.accessory_suitcase,
	'alias_file' : Files_and_suitcases.alias_file,
	'application_file' : Earlier_terms.application_file,
	'clipping' : Files_and_suitcases.clipping,
	'container' : container,
	'desk_accessory_file' : Files_and_suitcases.desk_accessory_file,
	'document_file' : Files_and_suitcases.document_file,
	'file' : Files_and_suitcases.file,
	'folder' : folder,
	'font_file' : Files_and_suitcases.font_file,
	'font_suitcase' : Files_and_suitcases.font_suitcase,
	'internet_location' : Earlier_terms.internet_location,
	'item' : Earlier_terms.item,
	'package' : Files_and_suitcases.package,
	'sharable_container' : sharable_container,
	'sound_file' : Files_and_suitcases.sound_file,
	'suitcase' : Files_and_suitcases.suitcase,
}
sharing_privileges._superclassnames = []
sharing_privileges._privpropdict = {
	'make_changes' : make_changes,
	'see_files' : see_files,
	'see_folders' : see_folders,
}
sharing_privileges._privelemdict = {
}
trash_2d_object._superclassnames = ['container']
trash_2d_object._privpropdict = {
	'_3c_Inheritance_3e_' : _3c_Inheritance_3e_,
	'warns_before_emptying' : warns_before_emptying,
}
trash_2d_object._privelemdict = {
	'accessory_suitcase' : Earlier_terms.accessory_suitcase,
	'alias_file' : Files_and_suitcases.alias_file,
	'application_file' : Earlier_terms.application_file,
	'clipping' : Files_and_suitcases.clipping,
	'container' : container,
	'desk_accessory_file' : Files_and_suitcases.desk_accessory_file,
	'document_file' : Files_and_suitcases.document_file,
	'file' : Files_and_suitcases.file,
	'folder' : folder,
	'font_file' : Files_and_suitcases.font_file,
	'font_suitcase' : Files_and_suitcases.font_suitcase,
	'internet_location' : Earlier_terms.internet_location,
	'item' : Earlier_terms.item,
	'package' : Files_and_suitcases.package,
	'sharable_container' : sharable_container,
	'sound_file' : Files_and_suitcases.sound_file,
	'suitcase' : Files_and_suitcases.suitcase,
}

#
# Indices of types declared in this module
#
_classdeclarations = {
	'cdis' : disk,
	'cdsk' : desktop_2d_object,
	'cfol' : folder,
	'ctnr' : container,
	'ctrs' : trash_2d_object,
	'priv' : sharing_privileges,
	'sctr' : sharable_container,
}

_propdeclarations = {
	'c@#^' : _3c_Inheritance_3e_,
	'capa' : capacity,
	'ects' : entire_contents,
	'frsp' : free_space,
	'gppr' : group_privileges,
	'gstp' : guest_privileges,
	'iprv' : privileges_inherited,
	'isej' : ejectable,
	'isrv' : local_volume,
	'istd' : startup,
	'lvis' : icon_size,
	'ownr' : owner_privileges,
	'pexa' : expandable,
	'pexc' : completely_expanded,
	'pexp' : expanded,
	'prvr' : see_files,
	'prvs' : see_folders,
	'prvw' : make_changes,
	'sdsk' : startup_disk,
	'sele' : selection,
	'sexp' : exported,
	'sgrp' : group,
	'shar' : shared,
	'smou' : mounted,
	'sown' : owner,
	'spro' : protected,
	'trsh' : trash,
	'vwnd' : view_options_window,
	'warn' : warns_before_emptying,
}

_compdeclarations = {
}

_enumdeclarations = {
}

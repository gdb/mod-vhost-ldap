"""\
minidom.py -- a lightweight DOM implementation.

parse( "foo.xml" )

parseString( "<foo><bar/></foo>" )

Todo:
=====
 * convenience methods for getting elements and text.
 * more testing
 * bring some of the writer and linearizer code into conformance with this
        interface
 * SAX 2 namespaces
"""

import string
_string = string
del string

from xml.dom import HierarchyRequestErr

# localize the types, and allow support for Unicode values if available:
import types
_TupleType = types.TupleType
try:
    _StringTypes = (types.StringType, types.UnicodeType)
except AttributeError:
    _StringTypes = (types.StringType,)
del types

import xml.dom
_Node = xml.dom.Node

class Node(_Node):
    allnodes = {}
    _debug = 0
    _makeParentNodes = 1
    debug = None
    childNodeTypes = ()
    
    def __init__(self):
        self.childNodes = []
        self.parentNode = None
        if Node._debug:
            index = repr(id(self)) + repr(self.__class__)
            Node.allnodes[index] = repr(self.__dict__)
            if Node.debug is None:
                Node.debug = _get_StringIO()
                #open( "debug4.out", "w" )
            Node.debug.write("create %s\n" % index)

    def __getattr__(self, key):
        if key[0:2] == "__":
            raise AttributeError, key
        # getattr should never call getattr!
        if self.__dict__.has_key("inGetAttr"):
            del self.inGetAttr
            raise AttributeError, key

        prefix, attrname = key[:5], key[5:]
        if prefix == "_get_":
            self.inGetAttr = 1
            if hasattr(self, attrname):
                del self.inGetAttr
                return (lambda self=self, attrname=attrname:
                                getattr(self, attrname))
            else:
                del self.inGetAttr
                raise AttributeError, key
        else:
            self.inGetAttr = 1
            try:
                func = getattr(self, "_get_" + key)
            except AttributeError:
                raise AttributeError, key
            del self.inGetAttr
            return func()

    def __nonzero__(self):
        return 1

    def toxml(self):
        writer = _get_StringIO()
        self.writexml(writer)
        return writer.getvalue()

    def hasChildNodes(self):
        if self.childNodes:
            return 1
        else:
            return 0

    def _get_firstChild(self):
        if self.childNodes:
            return self.childNodes[0]

    def _get_lastChild(self):
        if self.childNodes:
            return self.childNodes[-1]

    def insertBefore(self, newChild, refChild):
        if newChild.nodeType not in self.childNodeTypes:
            raise HierarchyRequestErr, \
                  "%s cannot be child of %s" % (repr(newChild), repr(self) )
        if newChild.parentNode is not None:
            newChild.parentNode.removeChild(newChild)
        if refChild is None:
            self.appendChild(newChild)
        else:
            index = self.childNodes.index(refChild)
            self.childNodes.insert(index, newChild)
            newChild.nextSibling = refChild
            refChild.previousSibling = newChild
            if index:
                node = self.childNodes[index-1]
                node.nextSibling = newChild
                newChild.previousSibling = node
            else:
                newChild.previousSibling = None
            if self._makeParentNodes:
                newChild.parentNode = self
        return newChild

    def appendChild(self, node):
        if node.nodeType not in self.childNodeTypes:
            raise HierarchyRequestErr, \
                  "%s cannot be child of %s" % (repr(node), repr(self) )
        if node.parentNode is not None:
            node.parentNode.removeChild(node)
        if self.childNodes:
            last = self.lastChild
            node.previousSibling = last
            last.nextSibling = node
        else:
            node.previousSibling = None
        node.nextSibling = None
        self.childNodes.append(node)
        if self._makeParentNodes:
            node.parentNode = self
        return node

    def replaceChild(self, newChild, oldChild):
        if newChild.nodeType not in self.childNodeTypes:
            raise HierarchyRequestErr, \
                  "%s cannot be child of %s" % (repr(newChild), repr(self) )
        if newChild.parentNode is not None:
            newChild.parentNode.removeChild(newChild)
        if newChild is oldChild:
            return
        index = self.childNodes.index(oldChild)
        self.childNodes[index] = newChild
        if self._makeParentNodes:
            newChild.parentNode = self
            oldChild.parentNode = None
        newChild.nextSibling = oldChild.nextSibling
        newChild.previousSibling = oldChild.previousSibling
        oldChild.nextSibling = None
        oldChild.previousSibling = None
        if newChild.previousSibling:
            newChild.previousSibling.nextSibling = newChild
        if newChild.nextSibling:
            newChild.nextSibling.previousSibling = newChild
        return oldChild

    def removeChild(self, oldChild):
        self.childNodes.remove(oldChild)
        if oldChild.nextSibling is not None:
            oldChild.nextSibling.previousSibling = oldChild.previousSibling
        if oldChild.previousSibling is not None:
            oldChild.previousSibling.nextSibling = oldChild.nextSibling            
        oldChild.nextSibling = oldChild.previousSibling = None
        
        if self._makeParentNodes:
            oldChild.parentNode = None
        return oldChild

    def normalize(self):
        L = []
        for child in self.childNodes:
            if child.nodeType == Node.TEXT_NODE:
                data = child.data
                if data and L and L[-1].nodeType == child.nodeType:
                    # collapse text node
                    node = L[-1]
                    node.data = node.nodeValue = node.data + child.data
                    node.nextSibling = child.nextSibling
                    child.unlink()
                elif data:
                    if L:
                        L[-1].nextSibling = child
                        child.previousSibling = L[-1]
                    else:
                        child.previousSibling = None
                    L.append(child)
                else:
                    # empty text node; discard
                    child.unlink()
            else:
                if L:
                    L[-1].nextSibling = child
                    child.previousSibling = L[-1]
                else:
                    child.previousSibling = None
                L.append(child)
                if child.nodeType == Node.ELEMENT_NODE:
                    child.normalize()
        self.childNodes[:] = L

    def cloneNode(self, deep):
        import new
        clone = new.instance(self.__class__, self.__dict__.copy())
        if self._makeParentNodes:
            clone.parentNode = None
        clone.childNodes = []
        if deep:
            for child in self.childNodes:
                clone.appendChild(child.cloneNode(1))
        return clone

    def unlink(self):
        self.parentNode = None
        for child in self.childNodes:
            child.unlink()
        self.childNodes = None
        self.previousSibling = None
        self.nextSibling = None
        if Node._debug:
            index = repr(id(self)) + repr(self.__class__)
            self.debug.write("Deleting: %s\n" % index)
            del Node.allnodes[index]

def _write_data(writer, data):
    "Writes datachars to writer."
    replace = _string.replace
    data = replace(data, "&", "&amp;")
    data = replace(data, "<", "&lt;")
    data = replace(data, "\"", "&quot;")
    data = replace(data, ">", "&gt;")
    writer.write(data)

def _getElementsByTagNameHelper(parent, name, rc):
    for node in parent.childNodes:
        if node.nodeType == Node.ELEMENT_NODE and \
            (name == "*" or node.tagName == name):
            rc.append(node)
        _getElementsByTagNameHelper(node, name, rc)
    return rc

def _getElementsByTagNameNSHelper(parent, nsURI, localName, rc):
    for node in parent.childNodes:
        if node.nodeType == Node.ELEMENT_NODE:
            if ((localName == "*" or node.tagName == localName) and
                (nsURI == "*" or node.namespaceURI == nsURI)):
                rc.append(node)
            _getElementsByTagNameNSHelper(node, nsURI, localName, rc)
    return rc

class Attr(Node):
    nodeType = Node.ATTRIBUTE_NODE
    attributes = None
    ownerElement = None
    childNodeTypes = (Node.TEXT_NODE, Node.ENTITY_REFERENCE_NODE)
    
    def __init__(self, qName, namespaceURI="", localName=None, prefix=None):
        # skip setattr for performance
        d = self.__dict__
        d["localName"] = localName or qName
        d["nodeName"] = d["name"] = qName
        d["namespaceURI"] = namespaceURI
        d["prefix"] = prefix
        Node.__init__(self)
        # nodeValue and value are set elsewhere

    def __setattr__(self, name, value):
        d = self.__dict__
        if name in ("value", "nodeValue"):
            d["value"] = d["nodeValue"] = value
        elif name in ("name", "nodeName"):
            d["name"] = d["nodeName"] = value
        else:
            d[name] = value

    def cloneNode(self, deep):
        clone = Node.cloneNode(self, deep)
        if clone.__dict__.has_key("ownerElement"):
            del clone.ownerElement
        return clone


class NamedNodeMap:
    """The attribute list is a transient interface to the underlying
    dictionaries.  Mutations here will change the underlying element's
    dictionary.

    Ordering is imposed artificially and does not reflect the order of
    attributes as found in an input document.
    """

    def __init__(self, attrs, attrsNS):
        self._attrs = attrs
        self._attrsNS = attrsNS

    def __getattr__(self, name):
        if name == "length":
            return len(self._attrs)
        raise AttributeError, name

    def item(self, index):
        try:
            return self[self._attrs.keys()[index]]
        except IndexError:
            return None

    def items(self):
        L = []
        for node in self._attrs.values():
            L.append((node.nodeName, node.value))
        return L

    def itemsNS(self):
        L = []
        for node in self._attrs.values():
            L.append(((node.URI, node.localName), node.value))
        return L

    def keys(self):
        return self._attrs.keys()

    def keysNS(self):
        return self._attrsNS.keys()

    def values(self):
        return self._attrs.values()

    def get(self, name, value = None):
        return self._attrs.get(name, value)

    def __len__(self):
        return self.length

    def __cmp__(self, other):
        if self._attrs is getattr(other, "_attrs", None):
            return 0
        else:
            return cmp(id(self), id(other))

    #FIXME: is it appropriate to return .value?
    def __getitem__(self, attname_or_tuple):
        if type(attname_or_tuple) is _TupleType:
            return self._attrsNS[attname_or_tuple]
        else:
            return self._attrs[attname_or_tuple]

    # same as set
    def __setitem__(self, attname, value):
        if type(value) in _StringTypes:
            node = Attr(attname)
            node.value = value
        else:
            if not isinstance(value, Attr):
                raise TypeError, "value must be a string or Attr object"
            node = value
        self.setNamedItem(node)

    def setNamedItem(self, node):
        old = self._attrs.get(node.name)
        if old:
            old.unlink()
        self._attrs[node.name] = node
        self._attrsNS[(node.namespaceURI, node.localName)] = node
        return old

    def setNamedItemNS(self, node):
        return self.setNamedItem(node)

    def __delitem__(self, attname_or_tuple):
        node = self[attname_or_tuple]
        node.unlink()
        del self._attrs[node.name]
        del self._attrsNS[(node.namespaceURI, node.localName)]
        self.length = len(self._attrs)

AttributeList = NamedNodeMap


class Element(Node):
    nodeType = Node.ELEMENT_NODE
    nextSibling = None
    previousSibling = None
    childNodeTypes = (Node.ELEMENT_NODE, Node.PROCESSING_INSTRUCTION_NODE,
                      Node.COMMENT_NODE, Node.TEXT_NODE,
                      Node.CDATA_SECTION_NODE, Node.ENTITY_REFERENCE_NODE)
    
    def __init__(self, tagName, namespaceURI="", prefix="",
                 localName=None):
        Node.__init__(self)
        self.tagName = self.nodeName = tagName
        self.localName = localName or tagName
        self.prefix = prefix
        self.namespaceURI = namespaceURI
        self.nodeValue = None

        self._attrs = {}   # attributes are double-indexed:
        self._attrsNS = {} #    tagName -> Attribute
                           #    URI,localName -> Attribute
                           # in the future: consider lazy generation
                           # of attribute objects this is too tricky
                           # for now because of headaches with
                           # namespaces.

    def cloneNode(self, deep):
        clone = Node.cloneNode(self, deep)
        clone._attrs = {}
        clone._attrsNS = {}
        for attr in self._attrs.values():
            node = attr.cloneNode(1)
            clone._attrs[node.name] = node
            clone._attrsNS[(node.namespaceURI, node.localName)] = node
            node.ownerElement = clone
        return clone

    def unlink(self):
        for attr in self._attrs.values():
            attr.unlink()
        self._attrs = None
        self._attrsNS = None
        Node.unlink(self)

    def getAttribute(self, attname):
        return self._attrs[attname].value

    def getAttributeNS(self, namespaceURI, localName):
        return self._attrsNS[(namespaceURI, localName)].value

    def setAttribute(self, attname, value):
        attr = Attr(attname)
        # for performance
        attr.__dict__["value"] = attr.__dict__["nodeValue"] = value
        self.setAttributeNode(attr)

    def setAttributeNS(self, namespaceURI, qualifiedName, value):
        prefix, localname = _nssplit(qualifiedName)
        # for performance
        attr = Attr(qualifiedName, namespaceURI, localname, prefix)
        attr.__dict__["value"] = attr.__dict__["nodeValue"] = value
        self.setAttributeNode(attr)

    def getAttributeNode(self, attrname):
        return self._attrs.get(attrname)

    def getAttributeNodeNS(self, namespaceURI, localName):
        return self._attrsNS[(namespaceURI, localName)]

    def setAttributeNode(self, attr):
        if attr.ownerElement not in (None, self):
            raise xml.dom.InuseAttributeErr("attribute node already owned")
        old = self._attrs.get(attr.name, None)
        if old:
            old.unlink()
        self._attrs[attr.name] = attr
        self._attrsNS[(attr.namespaceURI, attr.localName)] = attr

        # This creates a circular reference, but Element.unlink()
        # breaks the cycle since the references to the attribute
        # dictionaries are tossed.
        attr.ownerElement = self

        if old is not attr:
            # It might have already been part of this node, in which case
            # it doesn't represent a change, and should not be returned.
            return old

    def removeAttribute(self, name):
        attr = self._attrs[name]
        self.removeAttributeNode(attr)

    def removeAttributeNS(self, namespaceURI, localName):
        attr = self._attrsNS[(namespaceURI, localName)]
        self.removeAttributeNode(attr)

    def removeAttributeNode(self, node):
        node.unlink()
        del self._attrs[node.name]
        del self._attrsNS[(node.namespaceURI, node.localName)]

    def hasAttribute(self, name):
        return self._attrs.has_key(name)
                     
    def hasAttributeNS(self, namespaceURI, localName):
        return self._attrsNS.has_key((namespaceURI, localName))    
        
    def getElementsByTagName(self, name):
        return _getElementsByTagNameHelper(self, name, [])

    def getElementsByTagNameNS(self, namespaceURI, localName):
        _getElementsByTagNameNSHelper(self, namespaceURI, localName, [])

    def __repr__(self):
        return "<DOM Element: %s at %s>" % (self.tagName, id(self))

    def writexml(self, writer):
        writer.write("<" + self.tagName)

        attrs = self._get_attributes()
        a_names = attrs.keys()
        a_names.sort()

        for a_name in a_names:
            writer.write(" %s=\"" % a_name)
            _write_data(writer, attrs[a_name].value)
            writer.write("\"")
        if self.childNodes:
            writer.write(">")
            for node in self.childNodes:
                node.writexml(writer)
            writer.write("</%s>" % self.tagName)
        else:
            writer.write("/>")

    def _get_attributes(self):
        return AttributeList(self._attrs, self._attrsNS)

class Comment(Node):
    nodeType = Node.COMMENT_NODE
    nodeName = "#comment"
    attributes = None
    childNodeTypes = ()
    
    def __init__(self, data):
        Node.__init__(self)
        self.data = self.nodeValue = data

    def writexml(self, writer):
        writer.write("<!--%s-->" % self.data)

class ProcessingInstruction(Node):
    nodeType = Node.PROCESSING_INSTRUCTION_NODE
    attributes = None
    childNodeTypes = ()
    
    def __init__(self, target, data):
        Node.__init__(self)
        self.target = self.nodeName = target
        self.data = self.nodeValue = data

    def writexml(self, writer):
        writer.write("<?%s %s?>" % (self.target, self.data))

class Text(Node):
    nodeType = Node.TEXT_NODE
    nodeName = "#text"
    attributes = None
    childNodeTypes = ()
    
    def __init__(self, data):
        if type(data) not in _StringTypes:
            raise TypeError, "node contents must be a string"
        Node.__init__(self)
        self.data = self.nodeValue = data

    def __repr__(self):
        if len(self.data) > 10:
            dotdotdot = "..."
        else:
            dotdotdot = ""
        return "<DOM Text node \"%s%s\">" % (self.data[0:10], dotdotdot)

    def splitText(self, offset):
        if offset < 0 or offset > len(self.data):
            raise xml.dom.IndexSizeErr("illegal offset value")
        newText = Text(self.data[offset:])
        next = self.nextSibling
        if self.parentNode and self in self.parentNode.childNodes:
            if next is None:
                self.parentNode.appendChild(newText)
            else:
                self.parentNode.insertBefore(newText, next)
        self.data = self.data[:offset]
        return newText

    def writexml(self, writer):
        _write_data(writer, self.data)

def _nssplit(qualifiedName):
    fields = _string.split(qualifiedName, ':', 1)
    if len(fields) == 2:
        return fields
    elif len(fields) == 1:
        return ('', fields[0])


class DocumentType(Node):
    nodeType = Node.DOCUMENT_TYPE_NODE
    nodeValue = None
    attributes = None
    name = None
    publicId = None
    systemId = None
    internalSubset = ""
    entities = None
    notations = None

    def __init__(self, qualifiedName):
        Node.__init__(self)
        if qualifiedName:
            prefix, localname = _nssplit(qualifiedName)
            self.name = localname


class DOMImplementation:
    def hasFeature(self, feature, version):
        if version not in ("1.0", "2.0"):
            return 0
        feature = _string.lower(feature)
        return feature == "core"

    def createDocument(self, namespaceURI, qualifiedName, doctype):
        if doctype and doctype.parentNode is not None:
            raise xml.dom.WrongDocumentErr("doctype object owned by another DOM tree")
        doc = Document()
        if doctype is None:
            doctype = self.createDocumentType(qualifiedName, None, None)
        if qualifiedName:
            prefix, localname = _nssplit(qualifiedName)
            if prefix == "xml" \
               and namespaceURI != "http://www.w3.org/XML/1998/namespace":
                raise xml.dom.NamespaceErr("illegal use of 'xml' prefix")
            if prefix and not namespaceURI:
                raise xml.dom.NamespaceErr("illegal use of prefix without namespaces")
        doctype.parentNode = doc
        doc.doctype = doctype
        doc.implementation = self
        return doc

    def createDocumentType(self, qualifiedName, publicId, systemId):
        doctype = DocumentType(qualifiedName)
        doctype.publicId = publicId
        doctype.systemId = systemId
        return doctype


class Document(Node):
    nodeType = Node.DOCUMENT_NODE
    nodeName = "#document"
    nodeValue = None
    attributes = None
    doctype = None
    parentNode = None

    implementation = DOMImplementation()
    childNodeTypes = (Node.ELEMENT_NODE, Node.PROCESSING_INSTRUCTION_NODE,
                      Node.COMMENT_NODE, Node.DOCUMENT_TYPE_NODE)

    def appendChild(self, node):
        if node.nodeType not in self.childNodeTypes:
            raise HierarchyRequestErr, \
                  "%s cannot be child of %s" % (repr(node), repr(self) )
        if node.parentNode is not None:
            node.parentNode.removeChild(node)

        if node.nodeType == Node.ELEMENT_NODE \
           and self._get_documentElement():
            raise xml.dom.HierarchyRequestErr("two document elements disallowed")
        return Node.appendChild(self, node)

    def removeChild(self, oldChild):
        self.childNodes.remove(oldChild)
        oldChild.nextSibling = oldChild.previousSibling = None
        oldChild.parentNode = None
        if self.documentElement is oldChild:
            self.documentElement = None
             
        return oldChild

    def _get_documentElement(self):
        for node in self.childNodes:
            if node.nodeType == Node.ELEMENT_NODE:
                return node

    def unlink(self):
        if self.doctype is not None:
            self.doctype.unlink()
            self.doctype = None
        Node.unlink(self)

    createElement = Element

    createTextNode = Text

    createComment = Comment

    createProcessingInstruction = ProcessingInstruction

    createAttribute = Attr

    def createElementNS(self, namespaceURI, qualifiedName):
        prefix, localName = _nssplit(qualifiedName)
        return self.createElement(qualifiedName, namespaceURI,
                                  prefix, localName)

    def createAttributeNS(self, namespaceURI, qualifiedName):
        prefix, localName = _nssplit(qualifiedName)
        return self.createAttribute(qualifiedName, namespaceURI,
                                    localName, prefix)

    def getElementsByTagNameNS(self, namespaceURI, localName):
        _getElementsByTagNameNSHelper(self, namespaceURI, localName)

    def getElementsByTagName(self, name):
        rc = []
        _getElementsByTagNameHelper(self, name, rc)
        return rc

    def writexml(self, writer):
        for node in self.childNodes:
            node.writexml(writer)

def _get_StringIO():
    # we can't use cStringIO since it doesn't support Unicode strings
    from StringIO import StringIO
    return StringIO()

def _doparse(func, args, kwargs):
    events = apply(func, args, kwargs)
    toktype, rootNode = events.getEvent()
    events.expandNode(rootNode)
    return rootNode

def parse(*args, **kwargs):
    """Parse a file into a DOM by filename or file object."""
    from xml.dom import pulldom
    return _doparse(pulldom.parse, args, kwargs)

def parseString(*args, **kwargs):
    """Parse a file into a DOM from a string."""
    from xml.dom import pulldom
    return _doparse(pulldom.parseString, args, kwargs)

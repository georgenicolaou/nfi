'''
NFI -- Silensec's Nyuki Forensics Investigator

Copyright (C) 2014  George Nicolaou (george[at]silensec[dot]com)
                    Silensec Ltd.

This file is part of Nyuki Forensics Investigator (NFI).

NFI is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

NFI is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with NFI.  If not, see <http://www.gnu.org/licenses/>.
'''
from Catalog import Catalog
from IDeviceVersion import IDeviceVersion


class Label(object):
    '''
    Label class that is used when defining subsections of a catalog.
    
    Example: Label( "Device Information", "device_info" )
    
    Initialization arguments:
        - label, the name that you wish to be printed in the side-nav of the
                case's page.
        - internal_name, the internal name of this subsection used to identify
            and extract this subcatalog (auxiliary modules can use this)
    '''
    def __init__(self, label, internal_name):
        self.label = label
        self.internal_name = internal_name
class IMiscSource(object):
    version = []
    catalog_id = Catalog.CATALOG_NONE
    title = "Dummy Title"
    relative_directories = []
    knownfiles = {}
    
    def __init__(self):
        return
    
    def for_version(self,version):
        #Empty version means DEFAULT 
        if len(self.version) == 0:
            return True
        if IDeviceVersion.DEFAULT_VERSION in self.version:
            return True
        if version in self.version:
            return True
        return False
    
    def get_max_depth(self):
        return len(self.relative_directories)
    
    def get_relative_dir(self, depth=0):
        if len(self.relative_directories) > depth:
            return self.relative_directories[depth]
        else:
            return None

    
class FieldType(object):
    TYPE_STR = 1
    TYPE_INT = 2
    TYPE_DATA = 3
    #XML TYPE_CONTAINER searches for children in given element
    TYPE_CONTAINER = 4
    #XML TYPE_ARRAY searches for all nodes in given xml doc
    TYPE_ARRAY = 5 
    TYPE_DATE = 6
    

class KnownFieldMultiple(object): #XXX unused
    fieldtypes = []
    fieldnames = []
    descriptions = []
    regex_string = None
    def __init__(self, fieldtypes, regex_string, descriptions=None):
        self.fieldtypes = fieldtypes
        self.regex_string = regex_string
        self.descriptions = descriptions

class KnownField(object):
    '''
    A known field within a document. Initialized as such:
        - fieldtype, one of the FieldType class variables.
        - fieldregex, The regex string that captures the value of the element.
                      Make sure that the regex selector has a group in it
                      so that the parser can automatically capture the group's 
                      value. Note, the system only supports one group per field
        - internal_name, the internal name of this item.
        - description=None, textual description of this field which preceeds the
                      regex group name
        - contents=None, if the element is an array of identical elements and 
                    the KnownField value has been specified as TYPE_CONTAINER 
                    then this array contains the sub-element KnownField 
                    objects.
        - processor=None, function pointer to post processing processor to 
                    decode, decrypt or crack the value. For example, if this 
                    entry is a password hash then the value will be send a 
                    password cracking function.
    '''
    fieldtype = None
    internal_name = ""
    fieldname = None
    description = None
    converter = None
    contents = []
    canonical_name = None
    
    def __init__(self, fieldtype, fieldregex, internal_name, description=None, 
                 contents=None, processor=None, converter=None ):
        self.field_type = fieldtype
        self.fieldregex = fieldregex
        self.internal_name = internal_name
        self.description = description
        self.contents = contents
        self.converter = converter
        self.processor = processor
        return

"""
class FieldSearchXML(object):
    SEARCH_ALL = 0
    SEARCH_CONTENT = 1
    
    SEARCH_VALUE = 2
    SEARCH_ATTRIBUTE = 3
    GET_ATTRIBUTE = 4
"""
class ReadTypeXML(object):
    READ_TEXT = 0,
    READ_ATTR = 1
    
class KnownFieldXML(object):
    '''
    A known field within the XML document. Initialized as such:
        - fieldtype, one of the FieldType class variables.
        - xml_path, the XML path towards this element, using the 
                    xml.etree.ElementTree .find function.
        - description=None, textual description of this field
        - name, The canonical name of this entry within the store. This is to 
                avoid having to lookup elements using their description name.
        - read_type=ReadTypeXML.READ_TEXT, one of the ReadTypeXML class 
                    variables. READ_TEXT reads the contents of the XML dom 
                    element. READ_ATTR reads the specified attribute from the 
                    dom element.
        - attr=None, the textual name of the attribute to read if using 
                     READ_ATTR.
        - contents=None, if the element is an array of identical elements and 
                    the KnownFieldXML value has been specified as TYPE_ARRAY 
                    then this array contains the sub-element KnownFieldXML 
                    objects.
        - processor=None, function pointer to post processing processor to 
                    decode, decrypt or crack the value. For example, if this 
                    entry is a password hash then the value will be send a 
                    password cracking function.
        - converter=None, function that converts the value, eg date fields
    '''
    fieldtype = None
    xml_path = "" #xpath
    description = ""
    internal_name = ""
    attr = None
    contents = []
    processor = None
    converter = None
    def __init__(self, fieldtype, xml_path, internal_name, description=None, 
                 read_type=ReadTypeXML.READ_TEXT, attr=None, contents = [], 
                 processor=None, converter=None ):
        self.fieldtype = fieldtype
        self.xml_path = xml_path
        self.description = description
        self.read_type = read_type
        self.attr = attr
        self.internal_name = internal_name
        self.contents = contents
        self.processor = processor
        self.converter = converter
        return

class ParserType(object):
    TYPE_UNKNOWN = 0
    TYPE_REGEX = 1
    TYPE_XML = 2
    TYPE_BINARY = 3
    TYPE_SQLITE3 = 4
        
class KnownFile(object):
    parser = None
    knownfields = None #{"Text Description" : KnownField()}, ...
    def __init__(self, parser,knownfields):
        self.parser = parser
        self.knownfields = knownfields
        return
    
    
"""
Binary File Types:
"""

class Endianess(object):
    BIG_ENDIAN = '>'
    LITTLE_ENDIAN = '<'
    
class BinaryClass(object):
    '''
    The BinaryClass object tells the parser what kind of value it should expect
    in this field:
        - PRIMITIVE, is for primitive types such as byte, short, int values
        - ENUMERATION, this value is an enum. If ENUM then the "converter" value
                            should contain the dictionary which translates
                            integer values into strings. For example consider:
                            C code:
                            typedef enum VAL = { 
                                FIRST_ENUM=1,
                                SECOND_ENUM 
                            }
                            
                            Enum dictionary for this field:
                            enumdict = { 1: "FIRST_ENUM", 2: "SECOND_ENUM" }
        - FLAG_BITWISE, similar to enum but this is for flag fields. The
                        "converter" field must contain a similar dictionary with
                        flag values that will be bitwise-compared to the entry
                        to determine which flags are on or off.
        - FLAG_NUMERICAL, similar to FLAG_BITWISE but the "converter" field
                        contains actual numbers that are going to be compared
                        directly to the value of the field.
        - CONSUME, simply consume this field and don't populate it within the
                    store.
        - ANSI_STRING, specify that this is an ANSI string, the length can be
                        given at the BinaryRead field.
        - UNICODE_STRING, specify that this is a unicode string, it's length
                        can be given at the BinaryRead field.
        
        The following haven't been implemented yet
        - DECISION_VALUE, **NOT/MIGHT NOT BE IMPLEMENTED** 
                            This value represents fields that "decide" what the
                            next field would be. It would work a bit like the
                            container=[] of xml and regex fields but at the
                            moment I see no reason why this could be used. 
                            Please prove me wrong and it shall be implemented
                            promptly. 
        - POINTER_ABSOLUTE, that this field is a pointer(forwarder) to another
                            field that contains the offset to that field from
                            the beginning of the file
        - POINTER_RELATIVE, same as above but pointer is relative offset from
                            current location
    '''
    PRIMITIVE = 1
    POINTER_ABSOLUTE = 2
    POINTER_RELATIVE = 3
    ENUMERATION = 4
    FLAG_BITWISE = 5
    FLAG_NUMERICAL = 6
    CONSUME = 7
    ASCII_STRING = 8
    UTF8 = 9
    UTF16 = 10
    DATE = 11
    DECISION_VALUE = 12

class BinaryRead(object):
    '''
    The BinaryRead field designates how many bytes will be consumed to read this
    field. Eg, "how big this field is".
        - BYTE, consume 1 byte value
        - SHORT, consume 2 byte value
        - INTEGER, consume 4 byte value
        - ASCII_STRING, consume ANSI/UTF8 string until null byte is reached
        - UTF16_STRING, consume UTF-16 string until "null byte" is reached
        - EOF, consume until end of file
    
    **Note:**
        1. Providing a string value to this field will attempt to read the
            value of a previously parsed variable given a "field_name" attribute
            equal to that string. Note that the given field must be an integral
            value.
        2. Providing a function to this field will call that function, providing
            the dictionary of currently passed variable "field_name"s and 
            values as argument.
            The function must return an integer value signifying how many bytes
            to consume.
        3. Providing a number greater than zero specifies the exact number of
            bytes to consume for this field.
    '''
    BYTE = -1
    SHORT = -2
    INTEGER = -3
    ASCII_STRING = -4
    UTF16_STRING = -5
    EOF = -6
    
class KnownFieldBin(object):
    def __init__(self, binary_class, binary_read, field_name, description, 
                 converter=None, endianess=Endianess.BIG_ENDIAN ):
        '''
        Initialize a KnownFieldBin object for matching known binary files.
        Arguments:
            - binary_class, a BinaryClass value.
            - binary_read, a BinaryRead value.
            - field_name, an internal name used to identify this field.
            - description, the name/description of this field to be displayed
                            to the user. If description == None then this field
                            will not be displayed or populated to the user. The
                            value will however exist internally and can be
                            processed by subsequent field definitions. For
                            example in length fields.
            - converter, a function which converts this field to something the
                        program understands or a dictonary in case of fields
                        with BinaryClass values equal to ENUMERATION, 
                        FLAG_BITWISE or FLAG_NUMERICAL
            - endianess, the endianess of the value to read. The default one is
                        BIG_ENDIAN
        '''
        self.binary_class = binary_class
        self.binary_read = binary_read
        self.field_name = field_name
        self.description = description
        self.converter = converter
        self.endianess = endianess


"""
SQLite3 File Type -------------------------------------------------------------
"""

class KnownFieldSQL(object):
    def __init__(self, field_type, sql, description=None, internal_name=None, 
                 contents=None, converter=None ):
        '''
        Initialize a KnownFieldSQL object for matching values in SQLite files.
        Arguments:
            - field_type, a FieldType object value. Note that special values
                FieldType.TYPE_CONTAINER: is not accepted 
                FieldType.TYPE_ARRAY: denotes that the result is a multi-column
                array with one or more rows. Each object will then be parsed
                according to the KnonwFieldSQL in "contents" value
            - sql, The SQL command to execute to retrieve the object. If the
                    object is a child within the "contents" variable then this
                    must be null and the internal_name must be equal to the 
                    column name we are searching for.
            - contents, In case of FieldType.TYPE_ARRAY filed_type value this
                list contains the objects describing each column we wish to
                retrieve from the result of the SQL statement we just executed
            - internal_name, the internal name of this item. If this is a child
                item of a FieldType.TYPE_ARRAY object then this must be equal to
                the column's name we will be retrieving the value from.
            - converter, function pointer/object that converts this value before
                storing.
        '''
        self.field_type = field_type
        self.sql = sql
        self.description = description
        self.contents = contents
        self.internal_name = internal_name
        self.converter = converter
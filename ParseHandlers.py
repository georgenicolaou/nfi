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
import ExtractStore, SQLite3Initializer
import xml.etree.ElementTree as ET
import re,struct, itertools

from IMiscSource import FieldType, ReadTypeXML, BinaryRead, BinaryClass

store_types = {
    FieldType.TYPE_DATE: ExtractStore.TYPE_DATE,
    FieldType.TYPE_STR: ExtractStore.TYPE_STRING,
    FieldType.TYPE_INT: ExtractStore.TYPE_STRING,
    FieldType.TYPE_DATA: ExtractStore.TYPE_DATA,
}
def _parse_xml_knownfields( known_fields, root, print_queue ):
    items = []
    for known_field in known_fields:
        if known_field.fieldtype == FieldType.TYPE_CONTAINER:
            if len(known_field.contents) == 0: continue
            if type(known_field.xml_path) != list:
                xpaths = [known_field.xml_path]
            else:
                xpaths = known_field.xml_path
            for xpath in xpaths:
                node = root.find( xpath )
                if node == None:
                    continue
                #item = ExtractStore.MiscItem(item_type=ExtractStore.TYPE_MULTI)
                for child in node.getchildren():
                    imult = _parse_xml_knownfields( known_field.contents, child, 
                                                    print_queue )
                    if len(imult) == 0: continue
                    child_item = ExtractStore.MiscItem( 
                                    item_type=ExtractStore.TYPE_MULTI, 
                                    item_contents=imult )
                    #item.add_item( child_item )
                    items.append( child_item )
            #items.append(item)    
        elif known_field.fieldtype == FieldType.TYPE_ARRAY:
            if len(known_field.contents) == 0: continue
            if type(known_field.xml_path) != list:
                xpaths = [known_field.xml_path]
            else:
                xpaths = known_field.xml_path
            for xpath in xpaths:
                nodes = root.findall( xpath )
                #item = ExtractStore.MiscItem(item_type=ExtractStore.TYPE_MULTI)
                for node in nodes:
                    imult = _parse_xml_knownfields( known_field.contents, node, 
                                                    print_queue )
                    child_item = ExtractStore.MiscItem( 
                                    item_type=ExtractStore.TYPE_MULTI, 
                                    item_contents=imult )
                    #item.add_item( child_item )
                    items.append( child_item )
                #items.append(item)
        else:
            if known_field.read_type == ReadTypeXML.READ_TEXT:
                if type(known_field.xml_path) != list:
                    xpaths = [known_field.xml_path]
                else:
                    xpaths = known_field.xml_path
                for xpath in xpaths:
                    value = root.find( xpath ).text
                    if known_field.converter != None:
                        value = known_field.converter(value)
                    if value == None:
                        value = "N/A"
                    items.append( 
                        ExtractStore.MiscItem( 
                            store_types[known_field.fieldtype], 
                            known_field.description, value, 
                            item_name=known_field.internal_name
                        ) 
                    ) 
            elif known_field.read_type == ReadTypeXML.READ_ATTR:
                if type(known_field.xml_path) != list:
                    xpaths = [known_field.xml_path]
                else:
                    xpaths = known_field.xml_path
                for xpath in xpaths:
                    value = None
                    found_item = root.find( known_field.xml_path )
                    if found_item != None:
                        tags = found_item.items()
                        for tag in tags:
                            if tag[0] == known_field.attr:
                                value = tag[1]
                                break
                    if known_field.converter != None and value != None:
                        value = known_field.converter(value)
                    if value == None:
                        value = "N/A"
                    items.append( 
                        ExtractStore.MiscItem( 
                            store_types[known_field.fieldtype], 
                            known_field.description, value, 
                            item_name = known_field.internal_name 
                        ) 
                    )
            else:
                print "Not implemented read method"
    return items

def parse_xml( filename, filepath, known_info, print_queue, settings=None ):
    try:
        root = ET.parse(filepath)
    except:
        print "Error Parsing XML file"
        return None
    
    subsections = []
    for descr, known_fields in known_info.knownfields.iteritems():
        print_queue.put("\t[XML Parsing] Scanning: " + descr.label )
        items = _parse_xml_knownfields( known_fields, root, print_queue )
        subsection = ExtractStore.MiscSubSection( descr, items )
        subsections.append( subsection )
    return subsections

def _parse_regex_knownfields( known_fields, file_contents, print_queue ):
    items = []
    for known_field in known_fields:
        if known_field.field_type == FieldType.TYPE_CONTAINER:
            if len(known_field.contents) == 0: continue
            
            #Get all sub-contents of all items. Eg: network={ <this content> }
            item_contents = re.findall( known_field.fieldregex, file_contents )
            #For every content item of an entry
            for content in item_contents:
                if type(content) == tuple:
                    content = content[0]
                item = ExtractStore.MiscItem(item_type=ExtractStore.TYPE_MULTI, 
                                        item_name = known_field.internal_name )
                #Recurse and give the known_fields of this entry that are the
                #same for every entry
                item.add_multiple_items( _parse_regex_knownfields( 
                                                known_field.contents, content, 
                                                print_queue ) )
                items.append(item)    
        else: #We read everything else as strings 
            match = re.search( known_field.fieldregex, file_contents )
            if match == None: 
                value = "N/A"
            else:
                value = match.group(1)
            items.append( 
                ExtractStore.MiscItem(
                    store_types[known_field.field_type], 
                    known_field.description, 
                    value,
                    item_name = known_field.internal_name
                ) 
            )
    return items

def parse_regex( filename, filepath, known_info, print_queue, settings=None ):
    file_handle = open( filepath, "rb")
    file_contents = file_handle.read()
    file_handle.close()
    
    subsections = []
    for descr, known_fields in known_info.knownfields.iteritems():
        print_queue.put("\t[Regex Parsing] Scanning: " + descr.label )
        items = _parse_regex_knownfields( known_fields, file_contents, 
                                          print_queue )
        subsection = ExtractStore.MiscSubSection( descr, items )
        subsections.append(subsection)
    return subsections

def parse_keyval( filename, filepath, known_info, section, print_queue, settings=None ):
    return

def parse_ascii():
    return


primitive_info = {
    BinaryRead.BYTE : {"fmt": 'b', "size": 1 },
    BinaryRead.SHORT: {"fmt": 'h', "size": 2 },
    BinaryRead.INTEGER: { "fmt": 'i', "size": 4 }
}


def _parse_binary_knownfields( known_fields, file_contents, print_queue ):
    items = []
    temp_store = {}
    cur = 0 #cursor
    for field in known_fields:
        ': :type field IMiscSource.KnownFieldBin'
        
        #Reading actual value (BinaryRead)
        if field.binary_read in primitive_info:
            info = primitive_info[field.binary_read]
            val = struct.unpack(field.endianess+info['fmt'], 
                            file_contents[cur:cur+info['size']])
            if type(val) == tuple:
                val = val[0]
            else:
                val = None
            cur += info['size']
        elif field.binary_read == BinaryRead.ASCII_STRING:
            tmpval = itertools.takewhile( lambda c: c != '\x00', 
                                          file_contents[cur:] )
            cur += len(tmpval) + 1 #we skip the null byte too
            val = ''.join(tmpval)
        elif field.binary_read == BinaryRead.UTF16_STRING:
            #XXX should find a more pythonic way to do this...
            tmpval = []
            for c in file_contents[cur:]:
                if c == '\x00' and tmpval[-1:] == '\x00': break
                tmpval.append(c)
            tmpval = tmpval[:-1] #remove last null
            cur += len(tmpval) + 2
            val = ''.join(tmpval).decode("UTF-16")
        elif field.binary_read == BinaryRead.EOF:
            val = file_contents[cur:]
        elif callable(field.binary_read):
            (val,consume) = field.binary_read(temp_store,cur,file_contents)
            cur += consume
        elif type(field.binary_read) == int and field.binary_read > 0:
            val = file_contents[cur:cur+field.binary_read]
            cur += field.binary_read
        elif type(field.binary_read) == str:
            if field.binary_read in temp_store:
                size = temp_store[field.binary_read]
                if type(size) == int:
                    val = file_contents[cur:cur+size]
                    cur += size
                else:
                    print "Error: De-referencing value is not int"
        else:
            print "Error: Invalid BinaryRead value"
            continue
        
        #Interpreting value
        field_type = None
        if field.binary_class == BinaryClass.PRIMITIVE:
            field_type = FieldType.TYPE_INT
        elif field.binary_class in [ BinaryClass.ENUMERATION, 
                                    BinaryClass.FLAG_NUMERICAL]:
            if field.converter != None and type(field.converter) == dict:
                if val in field.converter:
                    val = field.converter[val]
            field_type = FieldType.TYPE_STR
        elif field.binary_class == BinaryClass.FLAG_BITWISE:
            if type(val) == int and type(field.converter) == dict:
                tmpstr = ""
                for flag,descr in field.converter.iteritems():
                    if type(flag) == int:
                        if flag & val != 0:
                            tmpstr += descr + " + "
                if len(tmpstr) != 0:
                    val = tmpstr[:-3] #remove " + "
            field_type = FieldType.TYPE_STR
        elif field.binary_class == BinaryClass.ASCII_STRING:
            field_type = FieldType.TYPE_STR
        elif field.binary_class == BinaryClass.UTF8:
            val = val.decode("UTF-8")
            field_type = FieldType.TYPE_STR
        elif field.binary_class == BinaryClass.UTF16:
            val = val.decode("UTF-16")
            field_type = FieldType.TYPE_STR
        elif field.binary_class == BinaryClass.DATE:
            field_type = FieldType.TYPE_DATE
        elif field.binary_class == BinaryClass.CONSUME:
            field_type == None
        else:
            print "Error: Invalid BinaryClass value"
            continue
    
        if field.converter != None:
            if field.binary_class not in [ BinaryClass.FLAG_BITWISE, 
                                          BinaryClass.FLAG_NUMERICAL, 
                                          BinaryClass.ENUMERATION ]:
                val = field.converter(val)
        
        temp_store[field.field_name] = val
        
        if field.binary_class != BinaryClass.CONSUME:
            item = ExtractStore.MiscItem( field_type, field.description, val, 
                                          item_name=field.field_name )
            items.append(item)
    return items

def parse_binary( filename, filepath, known_info, print_queue, settings=None ):
    file_handle = open( filepath, "rb" )
    file_contents = file_handle.read()
    file_handle.close()
    
    subsections = []
    for descr, known_fields in known_info.knownfields.iteritems():
        print_queue.put("\t[Binary Parsing] Scanning: " + descr.label )
        items = _parse_binary_knownfields( known_fields, file_contents, 
                                           print_queue )
        subsection = ExtractStore.MiscSubSection( descr, items )
        subsections.append( subsection )
    return subsections



"""
SQLite Parser -----------------------------------------------------------------
"""
import StringIO, sqlite3, tempfile, shutil,os

def _parse_sqlite_knownfield( known_fields, cursor, print_queue, contents=None ):
    items = []
    
    for known_field in known_fields:
        if known_field.field_type == FieldType.TYPE_ARRAY:
            #This is an array, we are expecting multiple rows
            try:
                res_obj = cursor.execute(known_field.sql)
            except sqlite3.OperationalError as e:
                print_queue.put("\t\t[SQLite3 Parsing]: Error: " + e.message )
                continue
            except:
                print_queue.put("\t\t[SQLite3 Parsing] Error: Bad SQL")
                continue
            res = res_obj.fetchall()
            for row in res:
                row_items = _parse_sqlite_knownfield( known_field.contents, 
                                                cursor, print_queue, row )
                tbl_item = ExtractStore.MiscItem(
                                        item_type=ExtractStore.TYPE_MULTI)
                tbl_item.add_multiple_items(row_items)
                items.append(tbl_item)
        elif known_field.sql == None:
            #This is a row element, we are expecting sql to be null
            if known_field.internal_name in contents:
                if known_field.converter != None:
                    contents[known_field.internal_name] = known_field.converter( 
                                        contents[known_field.internal_name] )
                item = ExtractStore.MiscItem( 
                            store_types[known_field.field_type], 
                            known_field.description, 
                            contents[known_field.internal_name], 
                            item_name=known_field.internal_name )
                items.append(item)
        else:
            try:
                res_obj = cursor.execute(known_field.sql)
                res = res_obj.fetchone()
                if res == None:
                    value = "N/A"
                elif len(res) == 0:
                    value = "N/A"
                elif len(res) != 1:
                    print_queue.put("\t\t[SQLite3 Parsing] Result Unexpected" + str(res))
                    value = "N/A"
                else:
                    value = res.values()[0]
                    if known_field.converter != None:
                        value = known_field.converter(value)
                items.append( ExtractStore.MiscItem( 
                            store_types[known_field.field_type], 
                            known_field.description, value, 
                            item_name=known_field.internal_name ) )
            except:
                print_queue.put("\t\t[SQLite3 Parsing] Error: Bad SQL")
    return items

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        if type(row[idx]) == buffer:
            d[col[0]] = StringIO.StringIO(row[idx])
        else:
            d[col[0]] = row[idx]
    return d

def parse_sqlite( filename, filepath, known_info, print_queue, settings=None ):
    tmpdir = tempfile.gettempdir()
    tmp_filepath = os.path.join( tmpdir, filename )
    print_queue.put( "\t[SQLite3 Parsing] Copying file: {} > {}".format( 
                                                    filepath, tmp_filepath ) )
    shutil.copy2( filepath, tmp_filepath )
    conn = sqlite3.connect(tmp_filepath)
    SQLite3Initializer.init_android(conn)
    conn.row_factory = dict_factory
    cur = conn.cursor()
    
    subsections = []
    for descr, known_fields in known_info.knownfields.iteritems():
        items = _parse_sqlite_knownfield( known_fields, cur, print_queue )
        subsection = ExtractStore.MiscSubSection( descr, items )
        subsections.append( subsection )
    return subsections
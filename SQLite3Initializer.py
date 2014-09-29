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


"""
Android SQLite Functions
"""
def func_phonenumb_equal(phone1,phone2,strict=False):
    #print "func_phonenumb_equal( {}, {}, {})".format(phone1,phone2,strict)
    if phone1 == None or phone2 == None: return None
    #XXX should probably split the number appart and do the check
    if strict:
        phone1 = phone1.replace(" ","").replace("+","")
        phone2 = phone2.replace(" ","").replace("+","")
        if phone1 == phone2: return 1
        return 0
    if phone1 == phone2: return 1
    return 0

def func_phonenumb_equal_2(phone1,phone2):
    return func_phonenumb_equal(phone1,phone2)

def func_phonenumb_equal_3(phone1,phone2,strict):
    return func_phonenumb_equal(phone1,phone2,strict)

def func_phone_stripped_reversed(phone):
    #print "func_phone_stripped_reversed( {} )".format(phone)
    return phone

def func_tokenize( token_table, data_row_id, data, delimiter, token_index=0, 
                   data_tag=None ):
    #print "func_tokenize( {}, {}, {}, {}, {}, {} )".format(token_table,
    #                            data_row_id,data,delimiter,token_index,data_tag)
    return None

def func_tokenize_4( token_table, data_row_id, data, delimiter ):
    return func_tokenize( token_table, data_row_id, data, delimiter )

def func_tokenize_5( token_table, data_row_id, data, delimiter, token_index ):
    return func_tokenize( token_table, data_row_id, data, delimiter, 
                          token_index )

def func_tokenize_6( token_table, data_row_id, data, delimiter, token_index, 
                     data_tag ):
    return func_tokenize( token_table, data_row_id, data, delimiter, 
                          token_index, data_tag )

def func_dummy_one(arg):
    #print "func_dummy_one( {} )".format(arg)
    return 1


"""
Collator functions
"""
def android_collate8(str1, str2):
    #print "android_collate8( {}, {} )".format(str1,str2)
    return cmp(str1,str2)

functions = {
    "_TOKNIZE": {"callable": func_tokenize_4, "args": 4 },
    "_TOKNIZE": {"callable": func_tokenize_5, "args": 5 },
    "_TOKNIZE": {"callable": func_tokenize_6, "args": 6 },
    "PHONE_NUMBERS_EQUAL": {"callable": func_phonenumb_equal_2, "args": 2},
    "PHONE_NUMBERS_EQUAL": {"callable": func_phonenumb_equal_3, "args": 3},
    "_DELETE_FILE": {"callable": func_dummy_one, "args": 1},
    "_LOG": {"callable": func_dummy_one, "args": 1 },
    "_PHONE_NUMBER_STRIPPED_REVERSED": { 
                        "callable": func_phone_stripped_reversed, "args": 1}
}
collators = {
    "PHONEBOOK" : android_collate8,
    "LOCALIZED" : android_collate8,
    "UNICODE": android_collate8,
    
}
def init_android(conn):
    '''
    Initializes Android database collators and functions for a given sqlite3
    connection object
    '''
    for name,func in collators.iteritems():
        conn.create_collation(name,func)
    for name,funcobj in functions.iteritems():
        conn.create_function( name, funcobj["args"], funcobj["callable"] )
    return


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
import sqlite3, os, tempfile, shutil
import biplist
import StringIO

TEMPDIR = "/tmp"

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        if type(row[idx]) == buffer:
            #We are converting buffer objects to StringIO so we can store it
            #using cPickle.
            d[col[0]] = StringIO.StringIO(row[idx])
        else:
            d[col[0]] = row[idx]
    return d

"""
Param info is the array for the database from an IApp known application.
Each element is a KnownTable class instance
"""
def get_known_table(info, tablename):
    for tblinfo in info:
        if tblinfo.name == tablename:
            return tblinfo
    return None

def handler_sqlite(filename, filepath, info, out=None, settings=None ):
    if out != None:
        out.put("\t[SQLite] Extracting: " + filepath)
    else:
        print "\t[SQLite] Extracting: " + filepath
    fobj = ExtractStore.ApplicationFile(filename,ExtractStore.TYPE_MULTI, 
                                        filepath=filepath)
    #establish connection
    if settings != None:
        tempfile.tempdir = settings.get("tempdir")
    tmpdir = tempfile.gettempdir()
    tmp_filepath = os.path.join(tmpdir,filename)
    if out != None:
        out.put("\t\t-> %s" % tmp_filepath)
    else:
        print "\t\t-> %s" % tmp_filepath
    shutil.copy2( filepath, tmp_filepath)
    conn = sqlite3.connect(tmp_filepath)
    conn.row_factory = dict_factory
    SQLite3Initializer.init_android(conn)
    cur = conn.cursor()
    #pull schema note that we also need to parse VIEWs but we need to define
    #collations and functions...
    schemaq = """
        SELECT name,type,sql
        FROM sqlite_master
        WHERE sql NOT NULL AND type == 'table' OR type == 'view'
    """
    cur.execute(schemaq)
    schema = cur.fetchall()
    knowntable = None
    for tblrow in schema:
        name = tblrow["name"]
        type = tblrow["type"]
        sql = tblrow["sql"]
        if name.startswith("sqlite_"):
            continue
        try:
            cur.execute("PRAGMA table_info('{name}')".format(name=name))
        except:
            continue
        columns = cur.fetchall()
        columns = [ col for col in columns if ":" not in col["name"] ]
        
        #columns = [{'name':str(c[1]),'type':str(c[2])} for c in fetch]
        if info != None:
            knowntable = get_known_table(info, name)
        if knowntable != None and knowntable.sql != None:
            cur.execute(knowntable.sql)
            res = cur.fetchall()
        else:
            if len(columns) != 0:
                q = "SELECT %s FROM %s" % (",".join( [c["name"] for c in columns] ), name )
                #print "Executing: " + q
                try:
                    cur.execute(q)
                except sqlite3.OperationalError as e:
                    out.put("[Error]: {}\n\tSQL: {}\n\tSkipping Table".format(
                                                                e.message,q))
                    continue
                except:
                    return handle_data(filename, filepath, info)
                res = cur.fetchall()
            else:
                res = []
        if knowntable != None:
            if knowntable.converter != None and len(knowntable.converter) != 0:
                for row in res:
                    for conv in knowntable.converter.keys():
                        try:
                            row[conv] = knowntable.converter[conv](row[conv])
                        except:
                            out.put( "**[ERROR]** Invalid Column Name: {}".format(conv))
        fobj.add_content(res, ExtractStore.TYPE_TABLE, name, columns, knowntable)
        #got all the data for this table + converted them
    cur.close()
    conn.close()
    os.remove(tmp_filepath)
    return fobj    

def handler_bplist(filename, filepath, info, out=None, settings=None ):
    if out != None:
        out.put("\t[PLIST] Extractiong: " + filepath)
    else:
        print "\t[PLIST] Extractiong: " + filepath
    
    try:
        plist = biplist.readPlist(filepath)
        content = biplist.writePlistToString(plist,False)
        fobj = ExtractStore.ApplicationFile(filename,ExtractStore.TYPE_XML)
        fobj.add_content(content)
        return fobj
    except:
        return handle_data(filename,filepath,info,out)

def handler_xml(filename, filepath,info, out=None, settings=None):
    if out != None:
        out.put("\t[XML] Extracting: " + filepath)
    else:
        print "\t[XML] Extracting: " + filepath
    fobj = ExtractStore.ApplicationFile(filename,ExtractStore.TYPE_XML)
    f = open(filepath,"r")
    fobj.add_content(f.read())
    f.close()
    return fobj

def handle_data(filename, filepath,info, out=None, settings=None):
    if out != None:
        out.put("\t[DATA] Extracting: " + filepath)
    else:
        print "\t[DATA] Extracting: " + filepath
    fobj = ExtractStore.ApplicationFile(filename,ExtractStore.TYPE_DATA)
    try:
        f = open(filepath, "rb")
        fobj.add_content(f.read())
        f.close()
    except:
        print "Error Reading File: " + filepath
    return fobj

def handle_image(filename, filepath, info, out=None, settings=None):
    if out != None:
        out.put("\t[IMAGE] Extracting: " + filepath)
    else:
        print "\t[IMAGE] Extracting: " + filepath
    fobj = ExtractStore.ApplicationFile(filename,ExtractStore.TYPE_IMAGE)
    f = open(filepath,"rb")
    fobj.add_content(f.read())
    f.close()
    return fobj

def handle_text(filename, filepath, info, out=None, settings=None):
    if out != None:
        out.put("\t[ASCII TEXT] Extracting: " + filepath)
    else:
        print "\t[ASCII TEXT] Extracting: " + filepath
    fobj = ExtractStore.ApplicationFile(filename,ExtractStore.TYPE_STRING)
    f = open(filepath,"r")
    fobj.add_content(f.read())
    f.close()
    return fobj
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
import sqlite3,os
import Queue, time, thread
from threading import Thread



dbschema = [   
    """CREATE TABLE officers ( 
        officer_id     INTEGER PRIMARY KEY AUTOINCREMENT, 
        officer_name   TEXT, 
        officer_badge  TEXT 
    )""",
    
    "CREATE INDEX officer_id ON officers ( officer_id )",
    
    """CREATE TABLE case_type ( 
        type_id     INTEGER PRIMARY KEY AUTOINCREMENT, 
        type_text   TEXT 
    )""",
    
    "CREATE INDEX type_id ON case_type ( type_id )",
    """INSERT INTO case_type ( type_id, type_text ) 
        VALUES ( 1, 'Logical Image Dump' )""",
        
    """INSERT INTO case_type ( type_id, type_text ) 
        VALUES ( 2, 'Device Backup Folder' )""",
    
    """CREATE TABLE cases ( 
        case_id          INTEGER PRIMARY KEY AUTOINCREMENT, 
        case_name        TEXT, 
        case_date        INTEGER, 
        case_comments    TEXT, 
        type_id          INTEGER, 
        case_appsmount   TEXT,
        case_sysmount    TEXT,
        case_scanned     BOOLEAN
    )""",
        
    "CREATE INDEX case_id ON cases ( case_id )",
    
    """CREATE TABLE case_store (
        cs_id      INTEGER    PRIMARY KEY AUTOINCREMENT,
        case_id    INTEGER,
        cs_path    TEXT
    )""",
    
    """CREATE TABLE case_file ( 
        cf_id INTEGER     PRIMARY KEY AUTOINCREMENT, 
        cf_location       TEXT, 
        cf_signature      TEXT, 
        cf_date_saved     INTEGER, 
        cf_date_accessed  INTEGER,
        cf_active         INTEGER,
        case_id           INTEGER
    )""",
    
    "CREATE INDEX cf_id ON case_file ( cf_id )",
    
    """CREATE TABLE case_officers ( 
        co_id         INTEGER PRIMARY KEY AUTOINCREMENT, 
        officer_id    INTEGER, 
        case_id       INTEGER 
    )""",
    
    """CREATE TRIGGER on_case_delete BEFORE DELETE ON cases 
        BEGIN
            DELETE FROM case_officers WHERE case_officers.case_id = old.case_id;
            DELETE FROM case_file WHERE case_file.case_id = old.case_id;
            DELETE FROM case_store WHERE case_store.case_id = old.case_id;
        END;
    """,
    
    """CREATE VIEW view_case_officers AS
        SELECT 
            case_officers.case_id, case_officers.officer_id, officers.officer_name
        FROM case_officers
        INNER JOIN officers ON case_officers.officer_id = officers.officer_id
    """
]

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

class DBCmd(object):
    cmd = None
    params = None
    result = None
    def __init__(self, cmd, params=None ):
        self.cmd = cmd
        self.params = params
        
class DBHandler(Thread):
    db = None
    dbq = None
    
    def _populate_db(self,conn):
        for statement in dbschema:
            conn.execute(statement)
    """
    def __del__(self,signal,frame):
        if self.db != None:
            print "Closing DB"
            self.db.close()
    """    
    def __init__(self, dbfile):
        Thread.__init__(self)
        self.dbq = Queue.Queue()
        self.dbfile = dbfile
        self.daemon = True
        self.start()
        return
    
    def run(self):
        exists = os.path.exists(self.dbfile)
        con = sqlite3.connect(self.dbfile)
        con.row_factory = dict_factory
        cur = con.cursor()
        if exists == False:
            self._populate_db(cur)
        con.commit()
        while True:
            req = self.dbq.get()
            
            if req.params != None:
                print "Executing: " + str(req.cmd) + " PARAMS: " + str(req.params)
                cur.execute(req.cmd, req.params)
            else:
                print "Executing: " + str(req.cmd)
                cur.execute(req.cmd)
            if req.cmd.upper().startswith("INSERT"):
                lastid = cur.lastrowid
                req.result.put(lastid)
            else:
                results = cur.fetchall()
                req.result.put(results)
            if not req.cmd.upper().startswith("SELECT"):
                con.commit()
    
    def _exec_sql(self, query, params=None):
        qobj = DBCmd(query,params)
        qobj.result = Queue.Queue()
        self.dbq.put(qobj)
        return qobj.result.get()
    
    def create_case(self, casename, officers, comments, ctype, apps, system):
        q = """INSERT INTO cases ( 
                case_name, 
                case_date, 
                case_comments, 
                type_id,  
                case_appsmount, 
                case_sysmount, 
                case_scanned 
            ) VALUES (?, ?, ?, ?, ?, ?, ?)"""
        cid = self._exec_sql(q, (casename, int(time.time()), comments, ctype, 
                                 apps, system, 0))
        
        for officer in officers:
            q = """INSERT INTO case_officers 
            ( officer_id, case_id ) VALUES ( ?, ? )"""
            self._exec_sql(q, (officer, cid))
        return cid
    
    """
    Update one or more fields from a table.
    Args:
        table: The table's name
        fields: Dictionary containing columns and values to update. For example:
                {'column_1': 1, 'column_2': 2}
        where: The WHERE string. Can also be used in conjuction with
                where_params for security. Eg: col_1 = ? AND col_2 = ?
        where_params: An array containing the parameters to replace question
                marks with to construct the SQL statement. eg: [1, 2]
    """
    def update(self, table, fields, where=None, where_params=None ):
        q = """UPDATE {tbl} SET """.format(tbl=table)
        q += ', '.join( "{col} = ?".format(col=key) for key in fields.iterkeys())
        params = fields.values()
        if where != None:
            q += " WHERE " + where
            if where_params != None:
                params += where_params
        return self._exec_sql(q, tuple(params))
    
    def add_case_file(self, case_id, case_filepath, file_signature):
        tstamp = int(time.time())
        self.update( "case_file", {"cf_active":0}, "case_id = ?", [case_id])
        q = """INSERT INTO 
            case_file ( 
                cf_location, 
                cf_signature,
                cf_date_saved, 
                cf_date_accessed,
                cf_active,
                case_id 
            ) VALUES
            ( ?, ?, '{t}', '{t}', '1', ? )""".format(t=tstamp)
        return self._exec_sql(q, (case_filepath, file_signature, case_id))
    
    def add_case_storepath(self, case_id, store_path):
        q = """INSERT INTO
            case_store (
                case_id,
                cs_path
            ) VALUES
            ( ?, ? )
        """
        return self._exec_sql(q, ( case_id, store_path ) )
    
    def get_case_storepath(self, case_id ):
        q = """SELECT cs_path FROM case_store WHERE case_id = ?"""
        result = self._exec_sql(q, (case_id,) )
        if len(result) != 0:
            return result[0]["cs_path"]
        return None
        
    def get_case_file(self, case_id, accessing=False, allfiles=None, cf_id=None):
        if allfiles == None: allfiles = False
        q = """SELECT 
                cf_id, 
                cf_location, 
                cf_signature, 
                cf_date_saved, 
                cf_date_accessed 
            FROM case_file
            WHERE case_id = ?"""
        
        if allfiles == False:
            if cf_id != None:
                q += """ AND cf_id = ?"""
                params = (case_id, cf_id)
            else:
                q += """ AND cf_active = 1"""
                params = (case_id,)
        else:
            params = (case_id,)
        case_files = self._exec_sql(q, params)
        if accessing:
            for case_file in case_files:
                q = """UPDATE case_file SET cf_date_accessed = {t} WHERE 
                    cf_id = ?""".format(t=int(time.time()))
                self._exec_sql(q, (case_file["cf_id"],))
                
        if len(case_files) == 0:
            return None
        elif allfiles:
            return case_files
        else:
            return case_files[0]
       
    def remove_case(self, case_id):
        q = """DELETE FROM cases WHERE case_id = ?"""
        return self._exec_sql(q, (case_id,))
    
    def get_officers(self):
        q = """SELECT officer_id, officer_name, officer_badge from officers"""
        return self._exec_sql(q)
    
    def add_officer(self, name, badge):
        q = "INSERT INTO officers ( officer_name, officer_badge ) VALUES ( ?, ?)"
        return self._exec_sql(q, (name, badge))
    
    def get_cases(self, case_id=None):
        query = """SELECT 
            cases.case_id as case_id, 
            case_name, 
            case_date, 
            case_comments,
            case_appsmount,
            case_sysmount,
            case_scanned,
            case_type.type_text as type_text,
            GROUP_CONCAT(view_case_officers.officer_name, ', ') as officers
        FROM cases
        INNER JOIN case_type ON cases.type_id = case_type.type_id
        INNER JOIN view_case_officers ON cases.case_id = view_case_officers.case_id"""
        group = """
        GROUP BY cases.case_id
        """

        if case_id != None:
            query += " WHERE cases.case_id = ? " + group
            result = self._exec_sql(query, [case_id])
        else:
            query += group
            result = self._exec_sql(query)

        if len(result) != 0:
            if result[0]['case_name'] == None:
                return []
        return result

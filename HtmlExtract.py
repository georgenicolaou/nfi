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
import os,cgi,string,re,StringIO
import ExtractStore
import shutil
import magic
import biplist
from IApp import DataTypes, IApp
import traceback,sys,base64
from MimeGuesser import MimeGuesser

class HtmlExtract(object):

    def __init__(self):
        self.datahandlers = {
            DataTypes.DATA: self.datahandler,
            DataTypes.DATE: self.datehandler,
            DataTypes.TEXT: self.texthandler
        }
        self.handlers = { 
            ExtractStore.TYPE_TABLE: self._get_tablehtml,
            ExtractStore.TYPE_DATA: self._get_datahtml,
            ExtractStore.TYPE_XML: self._get_xmlhtml,
            ExtractStore.TYPE_IMAGE: self._get_imagehtml,
            ExtractStore.TYPE_STRING: self._get_asciistringhtml
        }
        self.mime = MimeGuesser()
        
    def dump_file(self, appfile):
        html = ""
        if appfile.ftype == ExtractStore.TYPE_MULTI:
            navhead = """
            <div class="panel-heading">
                <ul class="nav nav-tabs">
            """
            navbody = """<div class="panel-body"><div class="tab-content">"""
            for contents in appfile.content:
                navhead += """<li><a data-toggle="tab" href="#{name}">{name}</a></li>""".format(name=contents.name)
                navbody += """<div id={name} class="tab-pane">""".format(name=contents.name)
                handler = None
                try:
                    handler=self.handlers[contents.ctype]
                except:
                    navbody += "No Handler Implemented"
                    #print "Bad Handler: " + appfile.name
                if handler != None:
                    navbody+=handler(contents.content,contents.tbl_info,contents.knowninfo)
                navbody += "</div>"
            navhead += "</ul></div>" #ul and panel-heading
            navbody += "</div></div>"
            html += """<div class="panel with-nav-tabs panel-default">
                    """ + navhead + navbody + """</div>"""
            #do the nav-tabs init here and add items
        else:
            handler = None
            try:
                handler = self.handlers[appfile.ftype]
            except:
                #print "No Handler: " + appfile.name
                html += "Error No Handler Implemented"
            if handler != None:
                html += handler(appfile.content, appfile.tbl_info)
        #html = html.encode("UTF-8")
        return html
    
    def dump_hex(self,appfile):
        if appfile.ftype == ExtractStore.TYPE_MULTI:
            if appfile.filepath == None:
                return "<p>Unexpected Error: no filepath specified</p>"
            try:
                f = open(appfile.filepath, "rb")
                content = f.read()
            except:
                return """
                <p>File {} not found. Please make sure that you haven't
                unmounted any images regarding this case
                """.format(cgi.escape(appfile.filepath))
            return self._get_datahtml(content)
        else:
            return self._get_datahtml(appfile.content)
    
    def dump_strings(self, appfile):
        if appfile.ftype == ExtractStore.TYPE_MULTI:
            if appfile.filepath == None:
                return "<p>Unexpected Error: no filepath specified</p>"
            try:
                f = open(appfile.filepath, "rb")
                content = f.read()
            except:
                return """
                <p>File {} not found. Please make sure that you haven't
                unmounted any images regarding this case
                """.format(cgi.escape(appfile.filepath))
            return self._get_stringshtml( self.restringsdump(content))
        else:
            return self._get_stringshtml(self.restringsdump(appfile.content))
    
    def datahandler(self, value):
        return """
                <button class="btn btn-primary btn-sm" onclick="hideshow(this);">
                Show Data <span class="glyphicon glyphicon-chevron-down"></span>
                </button>
                <pre style="display:none;">{hexdump}</pre>
        """.format(hexdump=self.hexdump(value))
        
    def datehandler(self, value):
        return """<span class="date">{value}</span>""".format(value=value)
    
    def texthandler(self,value):
        print "TEXTHANDLER CALLED"
        return "Unimplemented"
    
    def hexdump(self, src, length=16):
        if src == None:
            return "None"
        FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
        lines = []
        for c in xrange(0, len(src), length):
            chars = src[c:c+length]
            mhex = ' '.join(["%02x" % ord(x) for x in chars])
            printable = cgi.escape(''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars]))
            lines.append("%04x %-*s %s\n" % (c, length*3, mhex, printable))
        return ''.join(lines)
    
    def restringsdump(self, content):
        for match in re.finditer("[^\x00-\x1F\x7F-\xFF]{4,}", content):
            yield( match.start(), cgi.escape(match.group()) )
        
    def stringsdump(self, content, minlen=4):
        result = ""
        loc = 0
        for c in content:
            loc += 1
            if c in string.printable:
                result += c
                continue
            elif len(result) >= minlen:
                yield (loc, cgi.escape(result))
            result = ""
    def _parse_column(self, colname, value, tblinfo=None,knowntable=None,notd=False):
        ret = u""
        if isinstance( value, StringIO.StringIO ):
            value = value.buf
        if notd:
            valwrap = u"{value}"
        else:
            valwrap = u"<td>{value}</td>"
        knownfields = None
        if knowntable != None:
            knownfields = knowntable.knownfields
        if tblinfo != None:
            if colname in tblinfo:
                if tblinfo[colname] == "BLOB":
                    if value == None:
                        return valwrap.format(value="None")
                    mimetype = self.mime.get_buffermimetype(str(value), True)
                    if mimetype != None:
                        if mimetype.startswith("image/"):
                            return valwrap.format(value=self._get_imagehtml(value, {"mime":mimetype}))
                        elif mimetype.startswith("bplist"):
                            return valwrap.format(value=self._get_bplisthtml(value))
                    return valwrap.format(value=self.datahandler(value))
        try:
            if knownfields != None:
                if colname in knownfields:
                    return valwrap.format(value=self.datahandlers[knownfields[colname]](value))
            return valwrap.format(value=value)
        except Exception, e:
            if type(value) == StringIO:
                value = value.buf
            
            print traceback.format_exc()
            print "colname: {colname}".format(colname=colname)
            sys.stderr.write(repr(e) + "\n")
            # <button type="button" class="btn btn-primary btn-sm">Small button</button>
            return valwrap.format(value=self.datahandler(value))
        return ret
    
    def _get_tablehtml(self, content, tblinfo=None,knowntable=None):
        if len(content) == 0:
            return u"Empty"
        html = u"<script>TYPE="+str(ExtractStore.TYPE_TABLE)+"</script>"
        html += "<table class=\"todt\" style=\"width:100%\"><thead><tr>"
        first = content[0]
        for keyname in first.keys():
            html += "<th>{column}</th>".format(column=keyname)
        html += "</tr></thead></table>"
        return html
    
        for row in content:
            html += "<tr>"
            #print "row.keys = " + str(row.keys())
            for keyname in row.keys():
                html += self._parse_column(keyname, row[keyname], tblinfo,knowntable)
            html += "</tr>"
        html += "</tbody></table>"
        return html
    
    def _get_asciistringhtml(self, content, info=None, knowninfo=None):
        if len(content) == 0:
            return "Empty"
        html = """<pre>{strings}</pre>""".format(strings=content)
        return html
    
    def _get_datahtml(self, content, info=None, knowninfo=None):
        if len(content) == 0:
            return "Empty"
        
        html = """<pre>{hexdump}</pre>""".format(hexdump=self.hexdump(content))
        return html  

    def _get_stringshtml(self, strings ):
        html = "<pre>"
        for s in strings:
            html += "{loc}\t{s}\n".format(loc=s[0],s=s[1])
        html += "</pre>"
        return html
    
    def _get_xmlhtml(self, content, info=None, knowninfo=None, hidden=False):
        if len(content) == 0:
            return "Empty"
        try:
            if hidden:
                html = """<pre class="editor" style="display:none;">{xml}</pre>""".format(xml=cgi.escape(content.encode("UTF-8")))
            else:
                html = """<pre class="editor">{xml}</pre>""".format(xml=cgi.escape(content.encode("UTF-8")))
        except:
            return self._get_datahtml(content, info, knowninfo)
        return html
    
    def _get_imagehtml(self, content, info=None, knowninfo=None):
        #print "IMAGE NOT IMPLEMENTED"
        mime = "image/jpeg"
        if len(content) == 0:
            return "Empty"
        if info != None:
            if "mime" in info:
                mime = info["mime"]
        return """<img src="data:{mime};base64,{b64}"/>""".format(mime=mime, b64=base64.b64encode(content))
        return """<p>Not implemented</p>"""
    
    def _get_bplisthtml(self, buf):
        parsed = biplist.readPlistFromString(buf)
        html = """<button class="btn btn-primary btn-sm" onclick="hideshow(this);">
                Show XML <span class="glyphicon glyphicon-chevron-down"></span>
                </button>"""
        content = biplist.writePlistToString(parsed,False)
        html += self._get_xmlhtml(content, hidden=True) 
        return html
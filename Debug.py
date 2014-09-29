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
import cherrypy
import Catalog,ExtractStore

class Debug(object):


    def __init__(self,lookup,case):
        ':type case: HttpServe.Case'
        self.lookup = lookup
        self.case = case
        return
    
    def selfprint(self,msg,lvl=0):
        print ("\t" * lvl) + "[Debug]: " + msg
        
    def _get_item_html(self,item):
        html = u""
        if item.item_type == ExtractStore.TYPE_MULTI:
            html += u"""
            <li>
                <b>Label:</b>{}<br />
                <b>Name:</b>{}<br />
                <b>Value:</b>{}<br />
                <b>Type:</b>{}<br />
                <a href="#" class="itemslist"><i class="fa fa-plus"></i></a>
                """.format(item.item_label, item.item_name, item.item_value, 
                           item.item_type)
            html += u"""<ol style="display:none;">"""
            for subitem in item.item_contents:
                html += self._get_item_html(subitem)
            html += "</ol></li>"
        else:
            html += u"""
            <li>
                <b>Label:</b>{}<br />
                <b>Name:</b>{}<br />
                <b>Value:</b>{}<br />
                <b>Type:</b>{}<br />
            </li>""".format(item.item_label, item.item_name, item.item_value, 
                            item.item_type)
        return html
    
    def printCatalog(self,store):
        html = u""
        self.selfprint("Getting catalog")
        catalogs = store.misc_catalogs
        for catid,catalog in catalogs.iteritems():
            if catid not in Catalog.Catalog.catalogs_info: continue
            cat_info = Catalog.Catalog.catalogs_info[catid]
            self.selfprint("Rendering Catalog: {}".format(cat_info["name"]),1)
            html += u"""
            <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">{}</h3>
            </div>
            <div class="panel-body" style="display:none;">
            """.format( cat_info["name"] )
            for sec_name, section in catalog.sections.iteritems():
                html += "<h4>{} ({})</h4><ul>".format(sec_name,section.section_label)
                self.selfprint("Rendering section: " + section.section_label,2)
                for subsection in section.subsections:
                    self.selfprint("Rendering subsection: " + subsection.subsection_label,3)
                    html += """<li>
                        <h5>{} ({}) Items: </h5><a href="#" class="itemslist"><i class="fa fa-plus"></i></a>""".format( 
                        subsection.subsection_name, subsection.subsection_label)
                    html += """<ol style="display:none;">"""
                    for item in subsection.subsection_items:
                        html += self._get_item_html(item)
                    html += "</ol></li>"
                html += "</ul>"
                
            html += """
            </div>
            </div>
            """
        return html
    
    def _get_file_html(self,f):
        html = u"""
        <table>
            <tbody>
                <tr><th>name</th><td>{}</td></tr>
                <tr><th>ftype</th><td>{}</td></tr>
                <tr><th>type(content)</th><td>{}</td></tr>
                <tr><th>tbl_info</th><td>{}</td></tr>
                <tr><th>mime</th><td>{}</td></tr>
                <tr><th>sha256sig</th><td>{}</td></tr>
                <tr><th>knowninfo</th><td>{}</td></tr>
                <tr><th>filepath</th><td>{}</td></tr>
                <tr><th>atime</th><td>{}</td></tr>
                <tr><th>ctime</th><td>{}</td></tr>
                <tr><th>mtime</th><td>{}</td></tr>
                <tr><th>uid</th><td>{}</td></tr>
                <tr><th>gid</th><td>{}</td></tr>
                <tr><th>size</th><td>{}</td></tr>
                <tr><th>mode</th><td>{}</td></tr>
            </tbody>
        </table>
        """.format(
            f.name, f.ftype, str(type(f.content)), str(f.tbl_info), f.mime, f.sha256sig,
            f.knowninfo, f.filepath, f.atime, f.ctime, f.mtime, f.uid, f.gid,
            f.size,f.mode
        )
        return html
    
    def _get_directory_html(self,dirc):
        html = u""
        html += """
        <table>
            <tr><th>name</th><td>{}</td></tr>
            <tr><th># files</th><td>{}</td></tr>
            <tr><th># dirs</th><td>{}</td></tr>
        </table>
        """.format( dirc.name, len(dirc.files), len(dirc.directories))
        if( len(dirc.files) != 0 ):
            html+= "<p>Files:</p>"
            html += "<ol>"
            for f in dirc.files:
                html += "<li>"+self._get_file_html(f)+"</li>"
            html += "</ol>"
        if len( dirc.directories ) != 0:
            html+= "<p>Directories:</p><ol>"
            for d in dirc.directories:
                html += self._get_directory_html(d)
            html += "</ol>"
        return html
    
    def printApps(self,store):
        html = u""
        self.selfprint("Rendering apps")
        ': :type case: HttpServe.Case'
        for app in store.store:
            ': :type app: MiscStore.Application'
            self.selfprint("Rendering app: " + app.name, 1)
            html += u"""
            <div class="panel panel-default">
                <div class="panel-heading">
                    <h3 class="panel-title">{} ({})</h3>
                </div>
                <div class="panel-body" style="display:none;">
            """.format( app.name, app.cname )
            ': :type app: MiscStore.Application'
            tbl = u"""
            <table>
                <tbody>
                <tr><th>name</th><td>{}</td></tr>
                <tr><th>cname</th><td>{}</td></tr>
                <tr><th>totalfiles</th><td>{}</td></tr>
                <tr><th>installation_date</th><td>{}</td></tr>
                <tr><th>update_date</th><td>{}</td></tr>
                <tr><th>version</th><td>{}</td></tr>
                <tr><th>binary</th><td>{}</td></tr>
                <tr><th>app_user</th><td>{}</td></tr>
                <tr><th>installer</th><td>{}</td></tr>
                <tr><th>library_path</th><td>{}</td></tr>
                <tr><th>permissions</th><td>{}</td></tr>
                </tbody>
            </table>
            """.format(
                app.name, app.cname, app.totalfiles, app.installation_date,
                app.update_date, app.version, app.binary, app.app_user,
                app.installer, app.library_path, ', '.join(app.permissions)
            )
            dirhtml = "<ol>"
            for dirc in app.directories:
                dirhtml += "<li>{}</li>".format( self._get_directory_html(dirc) )
            dirhtml += "</ol>"
            html += tbl + dirhtml + "</div></div>"
        return html
    
    @cherrypy.expose
    def index(self,case_id):
        store = self.case.get_store(case_id)
        tmpl = self.lookup.get_template("debug.html")
        return tmpl.render_unicode(catalog=self.printCatalog(store),
                                   apps=self.printApps(store)) 
        
        
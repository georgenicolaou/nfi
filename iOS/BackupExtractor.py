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
import subprocess,os,re,zipfile

class BackupExtractor(object):
    def __init__(self, outdir, outqueue=None):
        self.outdir = outdir
        self.repat = re.compile("(?P<package>.+) - (?P<name>.+)")
        if os.path.exists(outdir) == False:
            os.mkdir(outdir)
        self.outqueue = outqueue
    
    def check_dependancies(self):
        deps = ["idevicebackup","idevicebackup2","ideviceinstaller"]
        ok_flag = True
        for app in deps:
            ok = "Ok"
            try:
                subprocess.call([app])
            except OSError as e:
                ok_flag = False
                if e.errno == os.errno.ENOENT:
                    ok = "Not installed"
                else:
                    ok = "Error {errno}: {error}".format(errno=e.errno, error=e.strerror)
            print "{lib}: {res}".format(lib=app,res=ok)
        return ok_flag
    
    
    def fullbackup(self,outdir):
        return
    
    def fullbackup2(self,outdir=None,device_id=None):
        if outdir == None:
            outdir = self.outdir
        elif os.path.exists(outdir) == False:
            os.mkdir(outdir)
        cmd = ["idevicebackup2", "backup", "--full"]
        if device_id != None:
            cmd.extend(["-u", device_id])
        cmd.append(outdir)
        self.runProc(cmd)
        
        if self.outqueue != None:
            self.outqueue.put("Unpacking backup")
        else:
            print "Unpacking Backup"
        
        self.runProc(["idevicebackup2", "unback", outdir])
        return
    
    def remove_backups(self):
        listcmd = ["ideviceinstaller", "-L"]
        remcmd = ["ideviceinstaller", "-R", "" ]
        
        archives = {}
        for line in self.runProcYield(listcmd):
            if line.startswith("Total") == False:
                res = self.repat.search(line)
                if res != None:
                    archives[res.group(1)] = res.group(2)
        for package,name in archives.iteritems():
            prt = "Removing: {name} ({package})".format(name=name,
                                                        package=package)
            if self.outqueue != None:
                self.outqueue.put(prt)
            else:
                print prt
            remcmd[2] = package
            subprocess.Popen(remcmd).communicate()
            
        
    def unzip(self,source,dest):
        try:
            f = zipfile.ZipFile(source)
            f.extractall(dest, f.infolist() )
        except:
            print "Unable to open ZIP file"
    def appbackup(self,outdir=None,device_id=None,full=False):
        if outdir == None:
            outdir = self.outdir
        elif os.path.exists(outdir) == False:
            os.mkdir(outdir)
        cmd = ["ideviceinstaller"]
        if device_id != None:
            cmd.extend(["-U", device_id])
        
        #first list
        listCmd = cmd[:]
        listCmd.append("-l")
        if full:
            listCmd.extend(["-o","list_all"])
        apps = {}
        for line in self.runProcYield(listCmd):
            if line.startswith("Total") == False:
                res = self.repat.search(line)
                if res != None:
                    apps[res.group(1)] = res.group(2)
        cmd.extend(["-a", "", "-o", "copy="+outdir])
        for package,name in apps.iteritems():
            prt = "Extracting: {name} ({package})".format(name=name,package=package)
            if self.outqueue != None:
                self.outqueue.put(prt)
            else:
                print prt
            cmd[2] = package
            print "Executing: " + ' '.join(cmd)
            subprocess.Popen(cmd).communicate()
            path = os.path.join(outdir,package)
            self.unzip( path+".ipa", path )
            print "OK"
    
    def runProc(self,cmd):
        print "RUNNING: " + str(cmd)
        p = subprocess.Popen(cmd,stdout=subprocess.PIPE,)
        while True:
            ret = p.poll()
            line = p.stdout.readline()
            if self.outqueue != None:
                self.outqueue.put(line)
            else:
                print line
            if ret != None:
                break
        return
    
    def runProcYield(self,cmd):
        print "RUNNING: " + str(cmd)
        p = subprocess.Popen(cmd,stdout=subprocess.PIPE,)
        while True:
            ret = p.poll()
            line = p.stdout.readline()
            yield line
            if ret != None:
                break
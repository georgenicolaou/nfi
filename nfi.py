#!/usr/bin/env python2.7
# encoding: utf-8
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
import sys
import os

from argparse import ArgumentParser
from argparse import RawDescriptionHelpFormatter
import tempfile
import importlib

__all__ = []
__version__ = 0.1
__date__ = '2014-05-14'
__updated__ = '2014-08-25'


class CLIError(Exception):
    '''Generic exception to raise and log different fatal errors.'''
    def __init__(self, msg):
        super(CLIError).__init__(type(self))
        self.msg = "E: %s" % msg
    def __str__(self):
        return self.msg
    def __unicode__(self):
        return self.msg

def check_dependencies():
    deps = {
        "cherrypy":[], 
        "mako":[], 
        "magic": ["from_buffer"], 
        "json":[], 
        "biplist":[]
    }
    for dep,functions in deps.iteritems():
        res = "Ok"
        try:
            mod = importlib.import_module(dep)
            moddir = dir(mod)
            for fun in functions:
                if fun not in moddir:
                    res = "Fail (Wrong dependency installed)"
                    break
        except:
            res = "Fail"
        print "{lib}: {res}".format(lib=dep,res=res)
    return


def main(argv=None):
    global TEMPDIR

    if argv is None:
        argv = sys.argv
    else:
        sys.argv.extend(argv)

    program_name = os.path.basename(sys.argv[0])
    program_version = "v%s" % __version__
    program_build_date = str(__updated__)
    program_version_message = '%%(prog)s %s (%s)' % (program_version, program_build_date)
    program_shortdesc = __import__('__main__').__doc__.split("\n")[1]
    program_license = '''%s
    Created by George Nicolaou on %s.
    Copyright 2014 Silensec Ltd. All rights reserved.

    NFI is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    NFI is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

USAGE
''' % (program_shortdesc, str(__date__))
    try:
        parser = ArgumentParser(description=program_license, 
                                formatter_class=RawDescriptionHelpFormatter)
        parser.add_argument('-V', '--version', action='version', 
                            version=program_version_message)
        parser.add_argument('-p', '--port', dest="port", action="store", 
                            help="Port to listen on", default="8080")
        parser.add_argument('-l', '--list', dest="list", action="store_true", 
                            help="List installed packages and plugins", 
                            default=False)
        parser.add_argument('-D', '--check-dependencies', dest="check", 
                            action="store_true", help="Check dependencies", 
                            default=False)
        parser.add_argument('-t', '--tempdir', dest="tmp", 
                            help="Specify the temporary directory for database"+
                            " reading operationgs [default=/tmp]", 
                            default="/tmp")
        parser.add_argument('-H', '--http', dest="daemon", 
                            help="Run in http mode", action="store_true", 
                            default=False)
        
        """
        parser.add_argument(dest="location", 
                            help="path to target (mounted location, file or " +
                            "output)", metavar="path", nargs='?', default=None )
        extractgroup = parser.add_argument_group()
        extractgroup.add_argument('-E', '--extract-backup', action="store_true", 
                                  dest="extract", help="Extract device backup")
        extractgroup.add_argument('-d', '--device-type', action="store", 
                                  dest="device", help="Specify device type", 
                                  choices=["android","ios"])
        extractgroup.add_argument('-u', '--device-id', action="store", 
                                  dest="uid", help="Device UUID", type=str)
        """
        

        args = parser.parse_args()
        #location = args.location
        #verbose = args.verbose
        check = args.check
        tempfile.tempdir = args.tmp
        if check == True:
            return check_dependencies()
        
        """
        if args.extract:
            if args.device == None:
                print "No device type specified"
                return
            if args.location == None:
                print "No output directory specified"
                return
            if args.device == "ios":
                from iOS.BackupExtractor import BackupExtractor as iosbackup
                backup = iosbackup(args.location)
                backup.remove_backups()
                backup.fullbackup2(os.path.join(args.location,"full"))
                backup.appbackup(os.path.join(args.location,"apps"),full=True)
            elif args.device == "android":
                print "Not implemented yet"
                return
            print "Location = " + args.location
            return
        """
        if args.list:
            print "Loading Packages, please wait..."
            from Android.ApplicationParser import ApplicationParser
            from Android.MiscParser import MiscParser
            parser = ApplicationParser()
            misc = MiscParser()
            lst = parser.get_package_list()
            print "{}:".format(parser.parser_name)
            for package in lst:
                print "\t{}".format(package)
            lst = misc.get_package_list()
            print "{}:".format(misc.parser_name)
            for package in lst:
                print "\t{}".format(package)
            return 0
        
        if args.daemon == True:
            from HttpServe import HttpServe
            http = HttpServe(port=args.port)
            http.serve()
            return
        """
        if args.recurse == True:
            #test
            from Android.AndroidScanner import AndroidScanner
            scanner = AndroidScanner(mountpoint=location)
            scanner.begin_scan( os.path.join(location,"data"))
            http = HttpServe(scanner.get_extractedstore(),port=args.port)
            http.serve()
            #ex = HtmlExtract(appparser.get_extractedstore())
            #ex.extract()
        """
        return 1
    except KeyboardInterrupt:
        ### handle keyboard interrupt ###
        return 0
    except Exception, e:
        import traceback
        print traceback.format_exc()
        indent = len(program_name) * " "
        sys.stderr.write(program_name + ": " + repr(e) + "\n")
        #sys.stderr.write(indent + "  for help use --help")
        return 2

if __name__ == "__main__":
    sys.exit(main())
# Nyuki Forensics Investigator

## Introduction

Nyuki Forensics Investigator is an open source application, that aims to provide 
a user friendly interface for the analysis of mobile device artefacts, that 
exist on Smartphone devices running the Android and iOS Operating System. It 
can be used to extract specific and aggregated information from individual 
applications and system files using a simple modular architecture, which is 
capable of accommodating any changes to individual artefacts.

Nyuki Forensics Investigator can be used by forensic analysts or mobile 
application penetration testers to analyze the contents of individual 
applications or global databases for information that can reveal user 
actions or internal application structures.

Nyuki Forensics Investigator was initially developed during an Android 
application penetration test in our spare time. It later grew into platform 
that students could use during the Mobile Forensic Bee™  course offered by 
Silensec ([read more](http://silensec.com/images/course-docs/Mobile%20Forensic.pdf)). Finally, it was decided that the application could 
become something more than a training assistant and thus we began developing 
what would later be called the Nyuki Forensics Investigator.

## Dependencies
Before running Nyuki Forensics Investigator there are several python modules 
we need to make sure we have in our system, namely:
* cherrypy: [http://www.cherrypy.org/]
* mako templates: [http://www.makotemplates.org/]
* python-magic: [https://github.com/ahupp/python-magic]
* biplist: [https://github.com/wooster/biplist]

You may install these packages using *pip* 
```
pip install cherrypy python-magic biplist mako
```

## Running
Execute the software using:
```
./nfi.py -H
```

For additional help execute:
```
./nfi.py --help
```

## More info
View more info at Silensec's Website [here](http://silensec.com/downloads-menu/nfi)
#!/usr/bin/python
# parseratproxy.py
#
# By Adrien de Beaupre adriendb@gmail.com | adrien@intru-shun.ca
# Copyright 2011 Intru-Shun.ca Inc. 
# v0.09
# 16 October 2011
#
# The current version of these scripts are at: http://dshield.handers.org/adebeaupre/ossams-parser.tgz
#
# Parses ratproxy output
# http://code.google.com/p/ratproxy/
#
#    This file is part of the ossams-parser.
#
#    The ossams-parser is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    The ossams-parser is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with the ossams-parser.  If not, see <http://www.gnu.org/licenses/>.
#

"""
As far as I can tell these are the heading values in the ratproxy log file, mapped to OSSAMS database fields. 
The vulnerability descriptions come from the messages.list file in ratproxy source code. The version of ratproxy
as at August 2011 was 1.58 beta, this file will have to be updated if anything changes in ratproxy. 

Severity: 			vulnerabilities.vulnerabilityseverity
Modifier: 
Name: 				vulnerabilities.vulnerabilityname
Offending value: 	vulnerabilities.httpparam
Response code: 		vulnerabilities.httpresponsecode
Length: 
Mime Type: 
Detected: 
Charset: 
Trace: 				vulnerabilities.httprequest and httpresponse
Method: 			vulnerabilities.httpmethod
URL: 				vulnerabilities.vulnerabilityuri
Cookies: 			vulnerabilities.httpcookie
Payload: 			vulnerabilities.vulnerabilityextra
Response:
"""

# parseratproxy function
def parseratproxy(time, os, etree, filetoread, db, dbconnection, projectname, projectid, separator):
	import string
	ratproxymessages = "xml" + separator + "ratproxymessages.xml"
	if os.path.isfile(ratproxymessages):
		pass
	else:
		print "The following file does not exist:", ratproxymessages
		return
	try:
		# Parse the XML file
		tree = etree.parse(ratproxymessages) 
		# Assign it to a variable as root
		root = tree.getroot()
	# What to do if the file does not parse
	except Exception, inst:
		print "\nError:"
		print "XML ElementTree parsing error opening %s: %s" % (ratproxymessages, inst)
		print
		return
	# Check to see if the document root is 'ratproxymessages', exit if it is not
	if root.tag:
		if root.tag != "ratproxymessages":
			print ratproxymessages, "is not a ratproxy messages XML file"
			return
	vulndict = {}
	versionelement = root.find('ratproxyversion')
	if versionelement is not None:
		if versionelement.text:
			version = versionelement.text
	else:
		version = "1.58 beta"
	names = root.findall('name')
	for name in names:
		if name.text:
			vulnname = name.text
		else:
			vulnname = ""
		description = name.find('description')
		if description is not None:
			if description.text:
				vulndesc = description.text
			else:
				vulndesc = ""
		vulndict[vulnname] = vulndesc
	ratproxyfile = filetoread.split(separator)
	file = ratproxyfile[-1]
	filetime = time.ctime(os.path.getmtime(filetoread))
	timenow = time.ctime()
	db.execute("""
		INSERT INTO tooloutput (toolname, filename, OSSAMSVersion, filedate, version, inputtimestamp, 
			projectname, projectid)
			VALUES
			('ratproxy', '%s', 0.09, '%s', '%s', '%s', '%s', '%s')
		""" % (file, filetime, version, timenow, projectname, projectid)
		)
	tooloutputnumber = int(db.lastrowid)
	print "Processed ratproxy report number:", tooloutputnumber
	db.execute("""
		INSERT INTO hosts (tooloutputnumber, recon, hostcriticality)
		VALUES
		('%s', '1', '0')
		""" % (tooloutputnumber)
		)
	hostnumber = int(db.lastrowid)
	ratproxyfile.pop()
	logfilehandle = open(filetoread, 'r')
	for line in logfilehandle:
		contents = line.split('|')
		counter = 0
		directory = ""
		for item in ratproxyfile:
			directory = directory  + item + separator
		tracefilefull = contents[9].split('/')
		tracefilename = directory + tracefilefull[-2] + separator + tracefilefull[-1]
		tracecontents = []
		if os.path.isfile(tracefilename):
			tracefilehandle = open(tracefilename, 'r')
			trace = tracefilehandle.read()
			tracefilehandle.close()
			tracecontents = trace.split('== SERVER RESPONSE')
			if tracecontents[0] is not None:
				if tracecontents[0] == string.whitespace or tracecontents[0] == "":
					request = ""
				else:
					requestpart = tracecontents[0]
					requestsplit = tracecontents[0].split('==')
					if requestsplit[2] is not None:
						request = requestsplit[2]
			else:
				request = ""
			if tracecontents[-1] is not None:
				if tracecontents[-1] == string.whitespace or tracecontents[-1] == "":
					response = ""
				else:	
					responsesplit = tracecontents[-1].split(' ==\n')
					if responsesplit[-2] is not None:
						response =  responsesplit[-2]
			else:
				response = ""
		else:
			request = ""
			response = ""
		description = vulndict[contents[2]]
		db.execute("""
		INSERT INTO vulnerabilities (tooloutputnumber, hostnumber, vulnerabilityseverity, vulnerabilityname, vulnerabilitydescription,
			vulnerabilityextra, vulnerabilityuri, httpcookie, httpmethod, httpparam, httprequest, httpresponse, vulnerabilityvalidation)
		VALUES
		('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '0')
		""" % (tooloutputnumber, hostnumber, contents[0], contents[2], description, contents[13], contents[11], contents[12],
				contents[10], contents[3], dbconnection.escape_string(request), dbconnection.escape_string(response))
		)
		vulnnumber = int(db.lastrowid)


				
#!/usr/bin/python
# parsewebsecurify.py
#
# By Adrien de Beaupre adriendb@gmail.com | adrien@intru-shun.ca
# Copyright 2011 Intru-Shun.ca Inc. 
# v0.09
# 16 October 2011
#
# The current version of these scripts are at: http://dshield.handers.org/adebeaupre/ossams-parser.tgz
#
# Parses websecurify XML output
# http://cirt.net/websecurify2
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

# parsewebsecurify function
def parsewebsecurify(time, os, root, filetoread, db, dbconnection, projectname, projectid, separator):
	# Check to see if the document root is 'items', exit if it is not
	if root.tag:
		if root.tag != "items":
			print filetoread, "is not a websecurify XML report file"
			return
	websecurifyfile = filetoread.split(separator)
	file = websecurifyfile[-1]
	filetime = time.ctime(os.path.getmtime(filetoread))
	timenow = time.ctime()
	db.execute("""
		INSERT INTO tooloutput (toolname, filename, OSSAMSVersion, filedate, inputtimestamp, projectname, projectid)
			VALUES
			('websecurify', '%s', 0.09, '%s', '%s', '%s', '%s')
		""" % (file, filetime, timenow, projectname, projectid)
		)
	tooloutputnumber = int(db.lastrowid)
	db.execute("""
		INSERT INTO hosts (tooloutputnumber, recon, hostcriticality)
		VALUES
		('%s', 1 ,0)
		""" % (tooloutputnumber)
		)
	hostnumber = int(db.lastrowid)
	elements = ['issue', 'level', 'title', 'summary', 'explanation', 'description']
	issues = {'issue': " ", 'level': " ", 'title': " ", 'summary': " ", 'explanation': " ", 'description': " ",
		'url': " ", 'request': " ", 'response': " "}
	items = root.findall('item')
	for item in items:
		for element in elements:
			found = item.find(element)
			if found is not None:
				if found.text:
					issues[element] = found.text
		fields = item.findall('details/field')
		for field in fields:
			if field.attrib:
				if field.get('name') == 'httpRequest':
					if field.text:
						issues['request'] = field.text
				if field.get('name') == 'httpResponseHeaders':
					if field.text:
						issues['response'] = field.text
				if field.get('name') == 'httpRequestUrl':
					if field.text:
						issues['url'] = field.text
		db.execute("""
		INSERT INTO vulnerabilities (tooloutputnumber, hostnumber, vulnerabilityvalidation, vulnerabilityid, vulnerabilityname, 
			vulnerabilityseverity, vulnerabilitydescription, vulnerabilityextra, vulnerabilityuri, httprequest, httpresponse)
			VALUES
			('%s', '%s', 0, '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')
			""" % (tooloutputnumber, hostnumber, issues['issue'], dbconnection.escape_string(issues['title']), issues['level'], 
				dbconnection.escape_string(issues['explanation']), dbconnection.escape_string(issues['description']),
				dbconnection.escape_string(issues['url']), dbconnection.escape_string(issues['request']), dbconnection.escape_string(issues['response']))
			)
		vulnnumber = int(db.lastrowid)

	print "Processed websecurify report number:", tooloutputnumber


	return

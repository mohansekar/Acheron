#!/usr/bin/python
# parsenetsparker.py
#
# By Adrien de Beaupre adriendb@gmail.com | adrien@intru-shun.ca
# Copyright 2011 Intru-Shun.ca Inc. 
# v0.09
# 16 October 2011
#
# The current version of these scripts are at: http://dshield.handers.org/adebeaupre/ossams-parser.tgz
#
# Parses netsparker XML output
# http://www.mavitunasecurity.com/netsparker/
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

# parsenetsparker function
def parsenetsparker(time, os, root, filetoread, db, dbconnection, projectname, projectid, separator):
	# Check to see if the document root is 'netsparker', exit if it is not
	if root.tag:
		if root.tag != "netsparker":
			print filetoread, "is not a netsparker XML report file"
			return
	# Take the root attributes and assign it to a dictionary
	if root.attrib:
		rootattribs = root.attrib
	netsparkerfile = filetoread.split(separator)
	file = netsparkerfile[-1]
	filetime = time.ctime(os.path.getmtime(filetoread))
	timenow = time.ctime()
	db.execute("""
		INSERT INTO tooloutput (toolname, filename, OSSAMSVersion, filedate, tooldate, inputtimestamp, projectname, projectid)
			VALUES
			('netsparker', '%s', 0.09, '%s', '%s', '%s', '%s', '%s')
		""" % (file, filetime, rootattribs['generated'], timenow, projectname, projectid)
		)
	tooloutputnumber = int(db.lastrowid)
	print "Processed netsparker report number:", tooloutputnumber
	target = root.find('target/url')
	if target is not None:
		if target.text:
			targeturl = target.text.split('/')
			hostname = targeturl[2]
		db.execute("""
			INSERT INTO hosts (tooloutputnumber, hostname, recon, hostcriticality)
			VALUES
			(%s, '%s', 1, 0)
			""" % (tooloutputnumber, hostname)
			)
		hostnumber = int(db.lastrowid)
	elements = ['url', 'type', 'severity', 'vulnerableparametertype', 'vulnerableparameter', 'vulnerableparametervalue', 'rawrequest', 'rawresponse']
	items = {}
	vulnerabilities = root.findall('vulnerability')
	for vuln in vulnerabilities:
		if vuln.attrib:	
			vulnerabilityconf = vuln.get('confirmed')
		for element in elements:
			item = vuln.find(element)
			if item is not None:
				if item.text:
					items[element] = item.text
				else:
					items[element] = " "
		extra = vuln.find('extrainformation/info')
		if extra is not None:
			if extra.attrib:
				extraname = extra.get('name')
			if extra.text:
				extrainfo = extra.text
		else:
			extraname = " "
			extrainfo = " "
		db.execute("""
			INSERT INTO vulnerabilities (tooloutputnumber, hostnumber, vulnerabilityuri, vulnerabilityname, vulnerabilityrisk, vulnerabilitydetails, httprequest, 
				httpresponse, httpparam, vulnerabilityextra, vulnerabilityattribute, vulnerabilityvalue, vulnerabilityvalidation)
				VALUES
				('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', 0)
				""" % (tooloutputnumber, hostnumber, dbconnection.escape_string(items['url']), items['type'], items['severity'], items['vulnerableparametertype'], 
				 dbconnection.escape_string(items['rawrequest']), dbconnection.escape_string(items['rawresponse']), items['vulnerableparameter'], 
				 dbconnection.escape_string(items['vulnerableparametervalue']), extraname, extrainfo)
			)
		vulnnumber = int(db.lastrowid)


				
		

	return

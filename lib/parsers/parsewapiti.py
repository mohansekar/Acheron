#!/usr/bin/python
# parsewapiti.py
#
# By Adrien de Beaupre adriendb@gmail.com | adrien@intru-shun.ca
# Copyright 2011 Intru-Shun.ca Inc. 
# v0.09
# 16 October 2011
#
# The current version of these scripts are at: http://dshield.handers.org/adebeaupre/ossams-parser.tgz
#
# Parses wapiti XML output
# wapiti.sourceforge.net
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

# parsewapiti function
def parsewapiti(time, os, root, filetoread, db, dbconnection, projectname, projectid, separator):
	# Check to see if the document root is 'wapiti', exit if it is not
	if root.tag:
		if root.tag != "report":
			print filetoread, "is not a wapiti XML report file."
			return
	if root.text:
		generated = root.text
	wapitifile = filetoread.split(separator)
	file = wapitifile[-1]
	filetime = time.ctime(os.path.getmtime(filetoread))
	timenow = time.ctime()
	generated = root.find('generatedBy')
	if generated is not None:
		if generated.attrib:
			if generated.get('id'):
				version = generated.get('id')
	db.execute("""
		INSERT INTO tooloutput (toolname, filename, OSSAMSVersion, filedate, inputtimestamp, projectname, projectid, version)
			VALUES
			('wapiti', '%s', 0.09, '%s', '%s', '%s', '%s', '%s')
		""" % (file, filetime, timenow, projectname, projectid, version)
		)
	tooloutputnumber = int(db.lastrowid)
	db.execute("""
		INSERT INTO hosts (tooloutputnumber, recon, hostcriticality)
		VALUES
		('%s', 1 ,0)
		""" % (tooloutputnumber)
		)
	hostnumber = int(db.lastrowid)
	bugelements = ['url', 'parameter', 'info']
	urlslist = []
	print "Processed wapiti report number:", tooloutputnumber
	bugs = root.findall('bugTypeList/bugType')
	for bug in bugs:
		bugvalues = {'name': " ", 'description': " ", 'solution': " ", 'level': " ", 'url': " ", 'parameter': " ", 'info': " "}
		urlslist = []
		if bug.attrib:
			if bug.get('name'):
				bugvalues['name'] = bug.get('name')
		refs = bug.findall('references/reference')
		for ref in refs:
			url = ref.find('url')
			if url is not None:
				if url.text:
					urlslist.append(url.text)
		desc = bug.find('description')
		if desc is not None:
			if desc.text:
				bugvalues['description'] = desc.text
				descencoded = bugvalues['description'].encode('utf-8','ignore')
		soln = bug.find('solution')
		if soln is not None:
			if soln.text:
				bugvalues['solution'] = soln.text
				solnencoded = bugvalues['solution'].encode('utf-8','ignore')
		buglists = bug.findall('bugList')
		for buglist in buglists:
			vulns = buglist.findall('bug')
			for vuln in vulns:
				if vuln.attrib:
					if vuln.get('level'):
						bugvalues['level'] = vuln.get('level')
				for elem in bugelements:
					node = vuln.find(elem)
					if node is not None:
						if node.text:
							bugvalues[elem] = node.text
				db.execute("""
				INSERT INTO vulnerabilities (tooloutputnumber, hostnumber, vulnerabilityvalidation, vulnerabilityname, 
					vulnerabilityseverity, vulnerabilitydescription, vulnerabilitysolution, vulnerabilityuri, httpparam, vulnerabilitydetails)
					VALUES
					('%s', '%s', 0, '%s', '%s', '%s', '%s', '%s', '%s', '%s')
					""" % (tooloutputnumber, hostnumber, bugvalues['name'], bugvalues['level'], dbconnection.escape_string(descencoded), 
						dbconnection.escape_string(solnencoded), dbconnection.escape_string(bugvalues['url']), 
						dbconnection.escape_string(bugvalues['parameter']), dbconnection.escape_string(bugvalues['info']) )
					)
				vulnnumber = int(db.lastrowid)
				for url in urlslist:
					db.execute("""
					INSERT into refs (tooloutputnumber, hostnumber, vulnerabilitynumber, referencetype, referencevalue)
						VALUES
						('%s', '%s', '%s', "url", '%s')
						""" % (tooloutputnumber, hostnumber, vulnnumber, dbconnection.escape_string(url))
						)
	return

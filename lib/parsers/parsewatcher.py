#!/usr/bin/python
# parsewatcher.py
#
# By Adrien de Beaupre adriendb@gmail.com | adrien@intru-shun.ca
# Copyright 2011 Intru-Shun.ca Inc. 
# v0.09
# 16 October 2011
#
# The current version of these scripts are at: http://dshield.handers.org/adebeaupre/ossams-parser.tgz
#
# Parses watcher XML output
# http://websecuritytool.codeplex.com/
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

# parsewatcher function
def parsewatcher(time, os, root, filetoread, db, dbconnection, projectname, projectid, separator):
	# Check to see if the document root is 'watcher', exit if it is not
	if root.tag:
		if root.tag != "watcher":
			print filetoread, "is not a watcher XML report file"
			return
	rootattribs = {'version' : ' ', 'date' : ' ', 'originDomain' : ' ', 'trustedDomains' : ' ', 'enabledChecks' : ' '}
	# Take the root attributes and assign it to a dictionary
	if root.attrib:
		rootattribs = root.attrib
	watcherfile = filetoread.split(separator)
	file = watcherfile[-1]
	filetime = time.ctime(os.path.getmtime(filetoread))
	timenow = time.ctime()
	db.execute("""
		INSERT INTO tooloutput (toolname, filename, OSSAMSVersion, filedate, tooldate, version, inputtimestamp, projectname, projectid)
			VALUES
			('watcher', '%s', 0.09, '%s', '%s', '%s', '%s', '%s', '%s')
		""" % (file, filetime, rootattribs['date'], rootattribs['version'], timenow, projectname, projectid)
		)
	tooloutputnumber = int(db.lastrowid)
	print "Processed watcher report number:", tooloutputnumber
	for config in ["originDomain", "trustedDomains", "enabledChecks"]:
		db.execute("""
			INSERT INTO configuration (tooloutputnumber, configurationoptionname, configurationoptionvalue)
			VALUES
			('%s', '%s', '%s')
				""" % (tooloutputnumber, config, dbconnection.escape_string(rootattribs[config]))
			)
	db.execute("""
		INSERT INTO hosts (tooloutputnumber, recon, hostcriticality)
		VALUES
		('%s', 1 ,0)
		""" % (tooloutputnumber)
		)
	hostnumber = int(db.lastrowid)
	# Iterate through all of the issues
	for issue in root.findall('issue'):
		# List for the children of issue element
		children = ['type', 'level', 'url', 'description']
		# Empty dictionary for the issue child element values
		issues = {'type': " ", 'level': " ", 'url': " ", 'description': " "}
		# Iterate through the child elements
		for child in children:
			# Find each of the issue element children in the list
			name = issue.find(child)
			# Grab the text values for each child element and assign to the dictionary
			if name is not None:
				if name.text:
					issues[child] = name.text
		db.execute("""
			INSERT INTO vulnerabilities (tooloutputnumber, hostnumber, vulnerabilityvalidation, vulnerabilityname, vulnerabilitydescription, vulnerabilityrisk, vulnerabilityuri)
			VALUES
			('%s', '%s', 0, '%s', '%s', '%s', '%s')
			""" % (tooloutputnumber, hostnumber, dbconnection.escape_string(issues['type']), dbconnection.escape_string(issues['description']), issues['level'], issues['url'])
			)
		vulnnumber = int(db.lastrowid)
	return



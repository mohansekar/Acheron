#!/usr/bin/python
# parsew3af.py
#
# By Adrien de Beaupre adriendb@gmail.com | adrien@intru-shun.ca
# Copyright 2011 Intru-Shun.ca Inc. 
# v0.09
# 16 October 2011
#
# The current version of these scripts are at: http://dshield.handers.org/adebeaupre/ossams-parser.tgz
#
# Parses w3af XML output
# http://w3af.sourceforge.net/
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

# parsew3af function
def parsew3af(time, os, root, filetoread, db, dbconnection, projectname, projectid, separator):
	# Check to see if the document root is 'w3afrun', exit if it is not
	if root.tag:
		if root.tag != "w3afrun":
			print filetoread, "is not a w3af XML report file."
			return
	if root.text:
		rootattribs = root.attrib
	w3affile = filetoread.split(separator)
	file = w3affile[-1]
	filetime = time.ctime(os.path.getmtime(filetoread))
	timenow = time.ctime()
	db.execute("""
		INSERT INTO tooloutput (toolname, filename, OSSAMSVersion, filedate, tooldate, version, inputtimestamp, projectname, projectid)
			VALUES
			('w3af', '%s', 0.09, '%s', '%s', 'unknown', '%s', '%s', '%s')
		""" % (file, filetime, rootattribs['startstr'], timenow, projectname, projectid)
		)
	tooloutputnumber = int(db.lastrowid)
	print "Processed w3af report number:", tooloutputnumber
	if root.find('scaninfo') is not None:
		scaninfo = root.find('scaninfo')
		if scaninfo.attrib:
			scaninfoattribs = scaninfo.attrib
			db.execute("""
				INSERT INTO hosts (tooloutputnumber, ipv4, hostname, recon, hostcriticality)
				VALUES
				(%s, '', '%s', 1, 0)
				""" % (tooloutputnumber, scaninfoattribs['target'])
				)
			hostnumber = int(db.lastrowid)
			print "Processed host:", hostnumber, "URI:", scaninfoattribs['target']
	elements = ['audit', 'bruteforce', 'grep', 'evasion', 'output', 'mangle', 'discovery']
	for element in elements:
		thiselement = scaninfo.find(element)
		if thiselement is not None:
			plugins = thiselement.findall('plugin')
			for plugin in plugins:
				if plugin.attrib:
					pluginattribs = plugin.attrib
				configs = plugin.findall('config')
				for config in configs:
					if config.attrib:
						configattribs = config.attrib
					else:
						configattribs = {'parameter': ' ', 'value': ' '}
					db.execute("""
					INSERT INTO configuration (tooloutputnumber, configurationtype, configurationoptionname, configurationoptionvalue)
					VALUES
					('%s', '%s', '%s', '%s')
					""" % (tooloutputnumber, pluginattribs['name'], configattribs['parameter'], dbconnection.escape_string(configattribs['value']))
					)
	vulnerabilities = root.findall('vulnerability')
	for vulnerability in vulnerabilities:
		if vulnerability.attrib:
			vulnattribs = vulnerability.attrib
			if 'id' not in vulnattribs:
				vulnattribs['id']= '0'
		if vulnerability.text:
			vulnattribs['desc'] = vulnerability.text
		db.execute("""
			INSERT INTO vulnerabilities (tooloutputnumber, hostnumber, vulnerabilityid, vulnerabilityrisk, vulnerabilityname, vulnerabilitydescription, vulnerabilityuri, httpparam, vulnerabilityattribute, vulnerabilityvalue, vulnerabilityvalidation)
			VALUES
			('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', 'method', '%s', 0)
			""" % (tooloutputnumber, hostnumber, vulnattribs['id'], vulnattribs['severity'], vulnattribs['name'], dbconnection.escape_string(vulnattribs['desc']), vulnattribs['url'], vulnattribs['var'], vulnattribs['method'])
			)
		vulnnumber = int(db.lastrowid)
	infos = root.findall('information')
	for info in infos:
		if info.attrib:
			infoattribs = info.attrib
			if 'id' not in infoattribs:
				infoattribs['id'] = '0'
		if info.text:
			infoattribs['desc'] = info.text
		db.execute("""
			INSERT INTO vulnerabilities (tooloutputnumber, hostnumber, vulnerabilityid, vulnerabilityrisk, vulnerabilityname, vulnerabilitydescription, vulnerabilityuri, vulnerabilityvalidation)
			VALUES
			('%s', '%s', '%s', 'informational', '%s', '%s', '%s', 0)
			""" % (tooloutputnumber, hostnumber, infoattribs['id'], infoattribs['name'], dbconnection.escape_string(infoattribs['desc']), infoattribs['url'])
			)
		vulnnumber = int(db.lastrowid)
	errors = root.findall('error')
	for error in errors:
		if error.attrib:
			errorattribs = error.attrib
		if error.text:
			errorattribs['desc'] = error.text
		db.execute("""
			INSERT INTO vulnerabilities (tooloutputnumber, hostnumber, vulnerabilityrisk, vulnerabilityname, vulnerabilitydescription, vulnerabilityvalidation)
			VALUES
			('%s', '%s', 'error', '%s', '%s', 0)
			""" % (tooloutputnumber, hostnumber, errorattribs['caller'], dbconnection.escape_string(errorattribs['desc']))
			)
		vulnnumber = int(db.lastrowid)

	return

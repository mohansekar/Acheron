#!/usr/bin/python
# parsenikto.py
#
# By Adrien de Beaupre adriendb@gmail.com | adrien@intru-shun.ca
# Copyright 2011 Intru-Shun.ca Inc. 
# v0.09
# 16 October 2011
#
# The current version of these scripts are at: http://dshield.handers.org/adebeaupre/ossams-parser.tgz
#
# Parses nikto XML output
# http://cirt.net/Nikto2
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

# parsenikto function
def parsenikto(time, os, root, filetoread, db, dbconnection, projectname, projectid, separator):
	# Check to see if the document root is 'niktoscan', exit if it is not
	if root.tag:
		if root.tag != "niktoscan":
			print filetoread, "is not a nikto XML report file"
			return
	rootattribs = {'hoststest' : ' ', 'options' : ' ', 'version' : ' ', 'scanstart' : ' ', 'scanend' : ' ', 'scanelapsed' : ' ', 'nxmlversion' : ' '}
	scandetailattribs = {'targetip' : ' ', 'targethostname' : ' ', 'targetport' : ' ', 'targetbanner' : ' ', 'starttime' :' ', 'sitename' : ' ', 'siteip' : ' ', 'hostheader' : ' '}
	items = {'id' : ' ', 'osvdbid' : ' ', 'osvdblink' : ' ', 'method' : ' '}
	statisticsattribs = {'elapsed' : ' ', 'itemsfound' :' ', 'itemstested' : ' ', 'endtime' : ' '}
	# Take the root attributes and assign it to a dictionary
	if root.attrib:
		rootattribs = root.attrib
		niktofile = filetoread.split(separator)
		file = niktofile[-1]
		filetime = time.ctime(os.path.getmtime(filetoread))
		timenow = time.ctime()
		db.execute("""
			INSERT INTO tooloutput (toolname, filename, OSSAMSVersion, filedate, tooldate, version, inputtimestamp, projectname, projectid)
				VALUES
				('nikto', '%s', 0.09, '%s', '%s', '%s', '%s', '%s', '%s')
			""" % (file, filetime, rootattribs['scanstart'], rootattribs['version'], timenow, projectname, projectid)
			)
		tooloutputnumber = int(db.lastrowid)
		db.execute("""
			INSERT INTO configuration (tooloutputnumber, configurationoptionname, configurationoptionvalue)
			VALUES
			('%s', "command line parameters", '%s')
				""" % (tooloutputnumber, rootattribs['options'])
			)

		print "Processed nikto report number:", tooloutputnumber
	# Grab the scandetails element
	scandetails = root.findall('scandetails')
	if scandetails:
		for scandetail in scandetails:
			if scandetail is not None:
				# Assign the scandetails attributes to a dictionary
				if scandetail.attrib:
					scandetailattribs = scandetail.attrib
					db.execute("""
					INSERT INTO hosts (tooloutputnumber, ipv4, hostname, recon, hostcriticality)
						VALUES
						('%s', '%s', '%s', 1, 0)
					""" % (tooloutputnumber, scandetailattribs['targetip'], scandetailattribs['targethostname'])
					)
					hostnumber = int(db.lastrowid)
					print "Processed host:", hostnumber, "IP:", scandetailattribs['targetip']
					db.execute("""
						INSERT INTO ports (tooloutputnumber, hostnumber, protocol, portnumber, portstate, portbanner )
							VALUES
							('%s', '%s', "tcp", '%s', "open", '%s')
						""" % (tooloutputnumber, hostnumber, scandetailattribs['targetport'], scandetailattribs['targetbanner'])
						)
					portsnumber = int(db.lastrowid)
			# Iterate through all of the items
			for item in scandetail.findall('item'):
				# gram all of the attributes into a dictionary
				if item.attrib:
					items = item.attrib
				# List of the item child elements
				children = ['description', 'uri', 'namelink', 'iplink']
				# Iterate through the child elements
				for child in children:
					# Find each of the issue element children in the list
					name = item.find(child)
					if name is not None:
						# Grab the text values for each child element and assign to the dictionary
						if name.text:
							items[child] = name.text
				db.execute("""
					INSERT INTO vulnerabilities (tooloutputnumber, hostnumber, vulnerabilityid, vulnerabilitydescription, vulnerabilityuri, vulnerabilityvalidation, portsnumber)
					VALUES
					('%s', '%s', '%s', '%s', '%s', 0, '%s')
						""" % (tooloutputnumber, hostnumber, items['id'], dbconnection.escape_string(items['description']), items['uri'], portsnumber)
					)
				vulnnumber = int(db.lastrowid)
				db.execute("""
					INSERT INTO refs (tooloutputnumber, hostnumber, vulnerabilitynumber, referencetype, referencevalue )
					VALUES
					('%s', '%s', '%s', "OSVDB", '%s')
						""" % (tooloutputnumber, hostnumber, vulnnumber, items['osvdbid'])
					)
			statistics = scandetail.find('statistics')
			if statistics is not None:
				if statistics.attrib:
					statisticsattribs = statistics.attrib
#		print ("Success")
	return

#!/usr/bin/python
# parseacunetix.py
#
# By Adrien de Beaupre adriendb@gmail.com | adrien@intru-shun.ca
# Copyright 2011 Intru-Shun.ca Inc. 
# v0.09
# 16 October 2011
#
# The current version of these scripts are at: http://dshield.handers.org/adebeaupre/ossams-parser.tgz
#
# Parses acunetix XML output
# http://www.acunetix.com
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

# parseacunetix function
def parseacunetix(time, os, root, filetoread, db, dbconnection, projectname, projectid, separator):
	# Check to see if the document root is 'ScanGroup', exit if it is not
	if root.tag != "ScanGroup":
		print filetoread, "is not a acunetix XML report file"
		return
	# Take the root attributes and assign it to a dictionary
	if root.attrib:
		rootattribs = root.attrib
		acunetixfile = filetoread.split(separator)
		file = acunetixfile[-1]
		filetime = time.ctime(os.path.getmtime(filetoread))
		timenow = time.ctime()
		db.execute("""
			INSERT INTO tooloutput (toolname, filename, OSSAMSVersion, filedate, tooldate, inputtimestamp, projectname, projectid)
				VALUES
				('acunetix', '%s', 0.09, '%s', '%s', '%s', '%s', '%s')
			""" % (file, filetime, rootattribs['ExportedOn'], timenow, projectname, projectid)
			)
		tooloutputnumber = int(db.lastrowid)
		print "Processed acunetix report number:", tooloutputnumber
	elements = ["Name", "ModuleName", "Details", "Affects", "IsFalsePositive", "Severity", "Type", "Impact", "Description", "Recommendation", "DetailedInformation"]
	scans = root.findall('Scan')
	for scan in scans:
		starturl = scan.find('StartURL')
		if starturl.text:
			starturlval = starturl.text
			noslashes = starturlval.replace('/','')
			stripped = noslashes.split(':')
			hostname = stripped[1] 
			port = stripped[-1]
		else:
			hostname = " "
			port = "0"
		banner = scan.find('Banner')
		if banner is not None:
			if banner.text:
				bannerval = banner.text
			else:
				bannerval = " "
		responsive = scan.find('Responsive')
		if responsive is not None:
			if responsive.text:
				responsetext = responsive.text
				if responsetext == "True":
					recon = 1
					portstate = 'open'
				else:
					recon = 0
					portstate = 'closed'
			else:
				responsetext = " "
		osguess = scan.find('Os')
		if osguess is not None:
			if osguess.text:
				osvalue = osguess.text
			else:
				osvalue = osguess.text
		db.execute("""
			INSERT INTO hosts (tooloutputnumber, hostname, recon, hostcriticality, hostos)
			VALUES
			(%s, '%s', '%s', 0, '%s')
			""" % (tooloutputnumber, hostname, recon, osvalue)
			)
		hostnumber = int(db.lastrowid)
		print "Processed host:", hostnumber, "Name: ", hostname
		db.execute("""
			INSERT INTO ports (tooloutputnumber, hostnumber, protocol, portnumber, portstate, portbanner)
			VALUES
			('%s', '%s', 'TCP', '%s', '%s', '%s')
			""" % (tooloutputnumber, hostnumber, port, portstate, dbconnection.escape_string(bannerval))
			)
		portnumber = int(db.lastrowid)
		reportitems = scan.findall('ReportItems/ReportItem')
		for reportitem in reportitems:
			items = {}
			for element in elements:
				elementitem = reportitem.find(element)
				if elementitem is not None:
					if elementitem.text:
						items[element] = elementitem.text
			if items['IsFalsePositive'] == 'True':
				falsepositive = 1
			else:
				falsepositive = 0
			request = reportitem.find('TechnicalDetails/Request')
			if request is not None:
				if request.text:
					httprequest = request.text
			else:
				httprequest = " "
			response = reportitem.find('TechnicalDetails/Response')
			if response is not None:
				if response.text:
					httpresponse = response.text
			else:
				httpresponse = " "
			db.execute("""
				INSERT INTO vulnerabilities (tooloutputnumber, hostnumber, vulnerabilityname, vulnerabilityrisk,  
					vulnerabilitydescription, vulnerabilitysolution, vulnerabilityextra, vulnerabilityvalidation, 
					vulnerabilityuri, portsnumber, falsepositive, httprequest, httpresponse)
				VALUES
				('%s', '%s', '%s', '%s', '%s', '%s', '%s', 0, '%s', '%s', '%s', '%s', '%s')
				""" % (tooloutputnumber, hostnumber, items['Name'], items['Severity'], dbconnection.escape_string(items['Description']), 
					dbconnection.escape_string(items['Recommendation']), dbconnection.escape_string(items['Impact']), items['Affects'], portnumber, falsepositive,
					dbconnection.escape_string(httprequest), dbconnection.escape_string(httpresponse))
				)
			vulnnumber = int(db.lastrowid)
			references = reportitem.findall('References/Reference')
			for reference in references:
				database = reference.find('Database')
				if database is not None:
					if database.text:
						referencetype = database.text
				url = reference.find('URL')
				if url is not None:
					if url.text:
						referencevalue= url.text
				db.execute("""
					INSERT INTO refs (tooloutputnumber, hostnumber, vulnerabilitynumber, referencetype, referencevalue )
					VALUES
					('%s', '%s', '%s', '%s', '%s')
					""" % (tooloutputnumber, hostnumber, vulnnumber, referencetype, referencevalue)
					)
	return

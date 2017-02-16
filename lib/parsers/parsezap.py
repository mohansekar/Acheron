#!/usr/bin/python
# parsezap.py
#
# By Adrien de Beaupre adriendb@gmail.com | adrien@intru-shun.ca
# Copyright 2011 Intru-Shun.ca Inc. 
# v0.09
# 16 October 2011
#
# The current version of these scripts are at: http://dshield.handers.org/adebeaupre/ossams-parser.tgz
#
# Parses zap XML output
# http://code.google.com/p/zaproxy/
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

# parsezap function
def parsezap(time, os, root, filetoread, db, dbconnection, projectname, projectid, separator):
	# Check to see if the document root is 'zap', exit if it is not
	if root.tag:
		if root.tag != "report":
			print filetoread, "is not a ZAP XML report file."
			return
	if root.text:
		generated = root.text
	zapfile = filetoread.split(separator)
	file = zapfile[-1]
	filetime = time.ctime(os.path.getmtime(filetoread))
	timenow = time.ctime()
	db.execute("""
		INSERT INTO tooloutput (toolname, filename, OSSAMSVersion, filedate, tooldate, inputtimestamp, projectname, projectid)
			VALUES
			('zap', '%s', 0.09, '%s', '%s', '%s', '%s', '%s')
		""" % (file, filetime, generated, timenow, projectname, projectid)
		)
	tooloutputnumber = int(db.lastrowid)
	db.execute("""
		INSERT INTO hosts (tooloutputnumber, recon, hostcriticality)
		VALUES
		('%s', 1 ,0)
		""" % (tooloutputnumber)
		)
	hostnumber = int(db.lastrowid)
	print "Processed ZAP report number:", tooloutputnumber
	alertitems = root.findall("alertitem")
	list = ['uri', 'param', 'otherinfo']
	items = {}
	for alertitem in alertitems:
		urilist = []
		paramlist = []
		otherlist = []
		if alertitem.find('pluginid').text:
			pluginid = alertitem.find('pluginid').text
		else:
			pluginid = " "
		if alertitem.find('alert').text:
			alert = alertitem.find('alert').text
		else:
			alert = " "
		if alertitem.find('riskcode').text:
			riskcode = alertitem.find('riskcode').text
		else:
			riskcode = " "
		if alertitem.find('reliability').text:
			reliability = alertitem.find('reliability').text
		else:
			reliability = " "
		if alertitem.find('riskdesc').text:
			riskdesc = alertitem.find('riskdesc').text
		else:
			riskdesc = " "
		if alertitem.find('desc').text:
			desc = alertitem.find('desc').text
		else:
			desc = " "
		if alertitem.find('solution').text:
			solution = alertitem.find('solution').text
		else:
			solution = " "
		if alertitem.find('reference').text:
			ref = alertitem.find('reference').text
		else:
			ref = " "
		uris = alertitem.findall('uri')
		for uri in uris:
			if uri.text:
				urilist.append(uri.text)
			else:
				urilist.append(" ")
		params = alertitem.findall('param')
		for param in params:
			if param.text:
				paramlist.append(param.text)
			else:
				paramlist.append(" ")
		others = alertitem.findall('otherinfo')
		for other in others:
			if other.text:
				otherlist.append(other.text)
			else:
				otherlist.append(" ")
		alluris = "URI, PARAM, OTHERINFO\n"
		for x in range(0,len(uris)):
			alluris = alluris + "uri: " + urilist[x] + " param: "  + paramlist[x] + " otherinfo: " + otherlist[x] +"\n"
		db.execute("""
		INSERT INTO vulnerabilities (tooloutputnumber, hostnumber, vulnerabilityvalidation, vulnerabilityid, vulnerabilityname, 
			vulnerabilityseverity, vulnerabilityconf, vulnerabilitydescription, vulnerabilitysolution, vulnerabilityextra)
			VALUES
			('%s', '%s', 0, '%s', '%s', '%s', '%s', '%s', '%s', '%s')
			""" % (tooloutputnumber, hostnumber, pluginid, dbconnection.escape_string(alert), riskcode, reliability, dbconnection.escape_string(desc), 
				dbconnection.escape_string(solution), dbconnection.escape_string(alluris))
			)
		vulnnumber = int(db.lastrowid)
		db.execute("""
		INSERT into refs (tooloutputnumber, hostnumber, vulnerabilitynumber, referencetype, referencevalue)
			VALUES
			('%s', '%s', '%s', "ZAP", '%s')
			""" % (tooloutputnumber, hostnumber, vulnnumber, dbconnection.escape_string(ref))
			)
	return

#!/usr/bin/python
# parseburp.py
#
# By Adrien de Beaupre adriendb@gmail.com | adrien@intru-shun.ca
# Copyright 2011 Intru-Shun.ca Inc. 
# v0.09
# 16 October 2011
#
# The current version of these scripts are at: http://dshield.handers.org/adebeaupre/ossams-parser.tgz
#
# Parses burp XML output
# http://portswigger.net/
# 
# If the XML bombs try this "sed 's/[[:cntrl:]]//g' $infile > $newinfile" at the command line 
# (replace $infile and $outfile with the correct filenames) then process the new file
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

# parseburp function
def parseburp(time, os, root, filetoread, db, dbconnection, projectname, projectid, separator):
	# Check to see if the document root is 'issues', exit if it is not
	if root.tag:
		if root.tag != "issues":
			print filetoread, "is not a burp XML report file."
			return
	if root.text:
		rootattribs = root.attrib
	burpfile = filetoread.split(separator)
	file = burpfile[-1]
	filetime = time.ctime(os.path.getmtime(filetoread))
	timenow = time.ctime()
	db.execute("""
		INSERT INTO tooloutput (toolname, filename, OSSAMSVersion, filedate, tooldate, version, inputtimestamp, projectname, projectid)
			VALUES
			('burp', '%s', 0.09, '%s', '%s', '%s', '%s', '%s', '%s')
		""" % (file, filetime, rootattribs['exportTime'], rootattribs['burpVersion'], timenow, projectname, projectid)
		)
	tooloutputnumber = int(db.lastrowid)
	print "Processed report number:", tooloutputnumber
	issues = root.findall('issue')
	elements = ['serialNumber', 'type', 'name', 'path', 'location', 'severity', 'confidence', 'issueBackground', 'remediationBackground', 'issueDetail']
	for issue in issues:
		issueresults = {"serialNumber": " ", "type": " ", "name": " ", "path": " ", "location": " ", "severity": " ", "confidence": " ", "issueBackground": " ",
					"remediationBackground": " ", "issueDetail": " ", "path": " ", "request": " ", "response": " "}
		host = issue.find('host')
		hostip = " "
		hostname = " "
		if host is not None:
			if host.attrib:
				hostip = host.get("ip")
			if host.text:
				hostname = host.text
			db.execute ("SELECT ipv4, hostname, hostnumber from hosts where ipv4 = '%s' and hostname = '%s'" % (hostip, hostname))
			row = db.fetchone ()
			if row == None:
				db.execute("""
				INSERT INTO hosts (tooloutputnumber, ipv4, hostname, recon, hostcriticality)
					VALUES
					('%s', '%s', '%s', 1, 0)
				""" % (tooloutputnumber, hostip, hostname)
				)
				hostnumber = int(db.lastrowid)
				print "Processed host:", hostnumber, "IP:", hostip
			else:
				hostnumber = row[2]
		for element in elements:
			issuedetail = issue.find(element)
			if issuedetail is not None:
				if issuedetail.text:
					issueresults[element] = issuedetail.text
		request = issue.find('requestresponse/request')
		if request is not None:
			if request.text:
				issueresults['request'] = request.text
		response = issue.find('requestresponse/response')
		if response is not None:
			if response.text:
				issueresults['response'] = response.text
		db.execute("""
			INSERT INTO vulnerabilities (tooloutputnumber, hostnumber, vulnerabilityid, vulnerabilityrisk, vulnerabilityconf, vulnerabilityname, 
				vulnerabilitydescription, vulnerabilitysolution, vulnerabilityextra, vulnerabilityuri, httprequest, httpresponse, vulnerabilityvalidation)
			VALUES
			('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', 0)
			""" % (tooloutputnumber, hostnumber, issueresults['type'], issueresults['severity'], issueresults['confidence'], dbconnection.escape_string(issueresults['name']),
				dbconnection.escape_string(issueresults['issueBackground']), dbconnection.escape_string(issueresults['remediationBackground']), 
				dbconnection.escape_string(issueresults['issueDetail']), dbconnection.escape_string(issueresults['path']), dbconnection.escape_string(issueresults['request']),
				dbconnection.escape_string(issueresults['response']))
		)
		vulnnumber = int(db.lastrowid)
	return

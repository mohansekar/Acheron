#!/usr/bin/python
# parseretinac.py
#
# By Adrien de Beaupre adriendb@gmail.com | adrien@intru-shun.ca
# Copyright 2011 Intru-Shun.ca Inc. 
# v0.09
# 16 October 2011
#
# The current version of these scripts are at: http://dshield.handers.org/adebeaupre/ossams-parser.tgz
#
# Parses retina community version XML output
# http://eeye.com
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

# parseretina function
def parseretinac(time, os, root, filetoread, db, dbconnection, projectname, projectid, separator):
	# Check to see if the document root is 'scanJob', exit if it is not
	if root.tag:
		if root.tag != "scanJob":
			print filetoread, "is not a retina XML report file"
			return
	retinafile = filetoread.split(separator)
	file = retinafile[-1]
	filetime = time.ctime(os.path.getmtime(filetoread))
	timenow = time.ctime()
	db.execute("""
		INSERT INTO tooloutput (toolname, filename, OSSAMSVersion, filedate, inputtimestamp, projectname, projectid)
			VALUES
			('retina', '%s', 0.09, '%s', '%s', '%s', '%s')
		""" % (file, filetime, timenow, projectname, projectid)
		)
	tooloutputnumber = int(db.lastrowid)
	print "Processed retina report number:", tooloutputnumber
	hostattribs = ['ip', 'netBIOSName', 'netBIOSDomain', 'dnsName', 'mac', 'os']
	auditattribs = ['rthID', 'cve', 'cce', 'name', 'description', 'date', 'risk', 'pciLevel', 'cvssScore', 'fixInformation', 'exploit']
	hosts = root.findall('hosts/host')
	for host in hosts:
		hostvalues = {'ip': " ", 'netBIOSName': " ", 'netBIOSDomain': " ", 'dnsName': " ", 'mac': " ", 'os': " "}
		auditvalues = {'rthID': " ", 'cve': " ", 'cce': " ", 'name': " ", 'description': " ", 'date': " ", 'risk': " ", 'pciLevel': " ", 
			'cvssScore': " ", 'fixInformation': " ", 'exploit': " "}
		refs = ['cve', 'cce', 'cvssScore', 'pciLevel']
		for value in hostattribs:
			node = host.find(value)
			if node.text:
				hostvalues[value] = node.text
		db.execute("""
		INSERT INTO hosts (tooloutputnumber, ipv4, macaddress, hostname, recon, hostcriticality, hostos)
			VALUES
			(%s, '%s', '%s', '%s', 1, 0, '%s')
			""" % (tooloutputnumber, hostvalues['ip'], hostvalues['mac'], hostvalues['dnsName'], hostvalues['os'])
			)
		hostnumber = int(db.lastrowid)
		print "Processed host:", hostnumber, "IP:", hostvalues['ip']
		audits = host.findall('audit')
		for audit in audits:
			for value in auditattribs:
				node = audit.find(value)
				if node.text:
					auditvalues[value] = node.text
			description = auditvalues['description']
			encodeddescription = description.encode('utf-8','ignore')
			db.execute("""
			INSERT INTO vulnerabilities (tooloutputnumber, hostnumber, vulnerabilityid, vulnerabilityname, vulnerabilityrisk,  
				vulnerabilitydescription, vulnerabilityvalidation, vulnerabilitysolution)
				VALUES
				('%s', '%s', '%s', '%s', '%s', '%s', 0, '%s')
				""" % (tooloutputnumber, hostnumber, auditvalues['rthID'], auditvalues['name'], auditvalues['risk'],
				dbconnection.escape_string(encodeddescription), dbconnection.escape_string(auditvalues['fixInformation'])
				)
			)
			vulnnumber = int(db.lastrowid)
			for ref in refs:
				refvalue = audit.find(ref)
				if refvalue.text:
					db.execute("""
						INSERT INTO refs (tooloutputnumber, hostnumber, vulnerabilitynumber, referencetype, referencevalue )
						VALUES
						('%s', '%s', '%s', '%s', '%s')
						""" % (tooloutputnumber, hostnumber, vulnnumber, refvalue.tag, refvalue.text)
						)

	return

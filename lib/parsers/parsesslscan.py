#!/usr/bin/python
# parsesslscan.py
#
# By Adrien de Beaupre adriendb@gmail.com | adrien@intru-shun.ca
# Copyright 2011 Intru-Shun.ca Inc. 
# v0.09
# 16 October 2011
#
# The current version of these scripts are at: http://dshield.handers.org/adebeaupre/ossams-parser.tgz
#
# Parses sslscan XML output
# http://sourceforge.net/projects/sslscan/
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

# parsesslscan function
def parsesslscan(time, os, root, filetoread, db, dbconnection, projectname, projectid, separator):
	# Check to see if the document root is 'sslscanscan', exit if it is not
	if root.tag:
		if root.tag != "document":
			print filetoread, "is not a sslscan XML report file."
			return
	# Take the root attributes and assign it to a dictionary
	rootattribs = {'title': " ", 'version': " ", 'web': " "}
	if root.attrib:
		rootattribs = root.attrib
	sslscanfile = filetoread.split(separator)
	file = sslscanfile[-1]
	filetime = time.ctime(os.path.getmtime(filetoread))
	timenow = time.ctime()
	db.execute("""
		INSERT INTO tooloutput (toolname, filename, OSSAMSVersion, filedate, inputtimestamp, projectname, version, projectid)
			VALUES
			('sslscan', '%s', 0.09, '%s', '%s', '%s', '%s', '%s')
		""" % (file, filetime, timenow, projectname, rootattribs['version'], projectid)
		)
	tooloutputnumber = int(db.lastrowid)
	print "Processed SSLscan report number:", tooloutputnumber
	# Grab the scandetails element
	ssltest = root.find('ssltest')
	# Assign the scandetails attributes to a dictionary
	ssltestattribs = {'host': " ", 'port': " "}
	cipherattribs = {'status': " ", 'sslversion': " ", 'bits': " ", 'cipher': " "}
	pkattribs = {'error': " ", 'type': " ", 'bits': " "}
	children = ['version', 'serial', 'signature-algorithm', 'issuer', 'not-valid-before', 'not-valid-after', 'subject', 'pk-algorithm', 'pk']
	certificates = {'version': " ", 'serial': " ", 'signature-algorithm': " ", 'issuer': " ", 'not-valid-before': " ", 'not-valid-after': " ", 'subject': " ", 'pk-algorithm': " ", 'pk': " "}
	if ssltest is not None:
		if ssltest.attrib:
			ssltestattribs = ssltest.attrib
			db.execute("""
			INSERT INTO hosts (tooloutputnumber, recon, hostcriticality, hostname)
			VALUES
			('%s', 1 ,0, '%s')
			""" % (tooloutputnumber, ssltestattribs['host'])
			)
			hostnumber = int(db.lastrowid)

		# Iterate through all of the ciphers
		ciphertest = ssltest.find('cipher')
		if ciphertest is not None:
			db.execute("""
			INSERT INTO ports (tooloutputnumber, hostnumber, protocol, portnumber, portstate, portattribute, portvalue)
			VALUES
			('%s', '%s', "TCP", '%s', "open", "SSL", "Enabled")
			""" % (tooloutputnumber, hostnumber, ssltestattribs['port'])
			)
			portsnumber = int(db.lastrowid)
			for cipher in ssltest.findall('cipher'):
				# Grab all of the attributes into a dictionary
				cipherattribs = cipher.attrib
				description = "status: " + cipherattribs['status'] + " SSlversion: " + cipherattribs['sslversion'] + " Bits: " + cipherattribs['bits'] + " Cipher: " + cipherattribs['cipher']
				db.execute("""
					INSERT INTO vulnerabilities (tooloutputnumber, hostnumber, portsnumber, vulnerabilityrisk, vulnerabilityname, vulnerabilitydescription)
					VALUES
					('%s', '%s', '%s', 'informational', 'SSL cipher state', '%s')
						""" % (tooloutputnumber, hostnumber, portsnumber, description)
					)
		else:
			db.execute("""
			INSERT INTO ports (tooloutputnumber, hostnumber, protocol, portnumber, portstate, portattribute, portvalue)
			VALUES
			('%s', '%s', "TCP", '%s', "unknown", "SSL", "disabled")
			""" % (tooloutputnumber, hostnumber, ssltestattribs['port'])
			)
			portsnumber = int(db.lastrowid)
		# Iterate through all of the defaultciphers
		for defaultcipher in ssltest.findall('defaultcipher'):
			# Grab all of the attributes into a dictionary
			if defaultcipher.attrib:
				defaultcipherattribs = defaultcipher.attrib
				description = "SSlversion: " + defaultcipherattribs['sslversion'] + " Bits: " + defaultcipherattribs['bits'] + " Cipher: " + defaultcipherattribs['cipher']
				db.execute("""
					INSERT INTO vulnerabilities (tooloutputnumber, hostnumber, portsnumber, vulnerabilityrisk, vulnerabilityname, vulnerabilitydescription)
					VALUES
					('%s', '%s', '%s', 'informational', 'SSL default cipher', '%s')
						""" % (tooloutputnumber, hostnumber, portsnumber, description)
					)
		# Grab the certificate element
		certificate = ssltest.find('certificate')
		# Iterate through the child elements
		if certificate is not None:
			for child in children:
				# Find each of the issue element children in the list
				name = certificate.find(child)
				# Grab the text values for each child element and assign to the dictionary
				if name is not None:
					certificates[child] = name.text
			pk = certificate.find('pk')
			if pk is not None:
				if pk.attrib:
					pkattribs = pk.attrib
		return



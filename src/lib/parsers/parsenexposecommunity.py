#!/usr/bin/python
# parsenexposecommunity.py
#
# By Adrien de Beaupre adriendb@gmail.com | adrien@intru-shun.ca
# Copyright 2011 Intru-Shun.ca Inc. 
# v0.09
# 16 October 2011
#
# The current version of these scripts are at: http://dshield.handers.org/adebeaupre/ossams-parser.tgz
#
# Parses nexpose community XML output
# http://rapid7.com
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

# parsenexposec function
def parsenexposec(time, os, root, filetoread, db, dbconnection, projectname, projectid, separator):
	# Check to see if the document root is 'NeXposeSimpleXML', exit if it is not
	if root.tag:
		if root.tag != "NeXposeSimpleXML":
			print filetoread, "is not a nexpose community XML report file"
			return
	nexposecfile = filetoread.split(separator)
	file = nexposecfile[-1]
	filetime = time.ctime(os.path.getmtime(filetoread))
	timenow = time.ctime()
	generated = root.find('generated')
	if generated.text:
		tooldate = generated.text
	else:
		tooldate = " "
	if root.attrib:
		if root.get('version') is not None:
			reportversion = root.get('version')
	db.execute("""
		INSERT INTO tooloutput (toolname, filename, OSSAMSVersion, filedate, tooldate, inputtimestamp, projectname, projectid)
			VALUES
			('nexposec', '%s', 0.09, '%s', '%s', '%s', '%s', '%s')
		""" % (file, filetime, tooldate, timenow, projectname, projectid)
		)
	tooloutputnumber = int(db.lastrowid)
	print "Processed nexpose community XML report number:", tooloutputnumber
	fingerelements = ['description', 'vendor', 'family', 'product', 'version', 'device-class', 'architecture']
	serviceelements = ['description', 'vendor', 'family', 'product', 'version']
	devices = root.findall('devices/device')
	for device in devices:
		fingervalues = {'description': " ", 'vendor': " ", 'family': " ", 'product': " ", 'version': " ", 'device-class': " ", 'architecture': " "}
		if device.attrib:
			if device.get('address') is not None:
				ip = device.get('address')
		fingerprint = device.find('fingerprint')
		if fingerprint is not None:
			if fingerprint.attrib:
				if fingerprint.get('certainty') is not None:
					fingervalues['certainty'] = fingerprint.get('certainty')
			for element in fingerelements:
				node = fingerprint.find(element)
				if node is not None:
					if node.text:
						fingervalues[element] = node.text
		db.execute("""
			INSERT INTO hosts (tooloutputnumber, ipv4, recon, hostcriticality, hostos, osgen, osfamily)
			VALUES
			(%s, '%s', 1, 0, '%s', '%s', '%s')
			""" % (tooloutputnumber, ip, fingervalues['description'], fingervalues['version'], fingervalues['family'])
			)
		hostnumber = int(db.lastrowid)
		print "Processed host:", hostnumber, "IP:", ip
		vulnerabilities = device.findall('vulnerabilities/vulnerability')
		for vulnerability in vulnerabilities:
			if vulnerability.attrib:
				if vulnerability.get('id') is not None:
					name = vulnerability.get('id')
				if vulnerability.get('resultCode') is not None:
					code = vulnerability.get('resultCode')
			db.execute("""
			INSERT INTO vulnerabilities (tooloutputnumber, hostnumber, vulnerabilityname, vulnerabilityextra, vulnerabilityvalidation)
				VALUES
				('%s', '%s', '%s', '%s', 0)
				""" % (tooloutputnumber, hostnumber, name, code)
			)
			vulnnumber = int(db.lastrowid)
			ids = vulnerability.findall('id')
			for id in ids:
				if id.text:
					refval = id.text
				else:
					refval = " "
				if id.attrib:
					if id.get('type') is not None:
						reftype = id.get('type')
					else:
						reftype = " "
				db.execute("""
					INSERT INTO refs (tooloutputnumber, hostnumber, vulnerabilitynumber, referencetype, referencevalue )
					VALUES
					('%s', '%s', '%s', '%s', '%s')
					""" % (tooloutputnumber, hostnumber, vulnnumber, reftype, refval)
					)
		services = device.findall('services/service')
		for service in services:
			servicevalues = {'name': ' ', 'port': " ", 'protocol': " ", 'certainty': " ", 'description': " ", 'vendor': " ", 
				'family': " ", 'product': " ", 'version': " "}
			if service.attrib:
				if service.get('name') is not None:
					servicevalues['name'] = service.get('name')
				if service.get('port') is not None:
					servicevalues['port'] = service.get('port')
				if service.get('protocol') is not None:
					servicevalues['protocol'] = service.get('protocol')
			fingerprint = service.find('fingerprint')
			if fingerprint is not None:
				if fingerprint.attrib:
					if fingerprint.get('certainty'):
						servicevalues['certainty'] = fingerprint.get('certainty')
				for element in serviceelements:
					node = fingerprint.find(element)
					if node is not None:
						servicevalues[element] = node.text
			db.execute("""
				INSERT INTO ports (tooloutputnumber, hostnumber, protocol, portnumber, portstate, portname, portbanner, service, portversion, confidence)
				VALUES
				('%s', '%s', '%s', '%s', 'open', '%s', '%s', '%s', '%s', '%s')
				""" % (tooloutputnumber, hostnumber, servicevalues['protocol'], servicevalues['port'], servicevalues['name'], 
					servicevalues['description'], servicevalues['product'], servicevalues['version'], servicevalues['certainty'])
				)
			portsnumber = int(db.lastrowid)
			vulnerabilities = service.findall('vulnerabilities/vulnerability')
			for vulnerability in vulnerabilities:
				if vulnerability.attrib:
					if vulnerability.get('id') is not None:
						name = vulnerability.get('id')
					if vulnerability.get('resultCode') is not None:
						code = vulnerability.get('resultCode')
				db.execute("""
				INSERT INTO vulnerabilities (tooloutputnumber, hostnumber, vulnerabilityname, vulnerabilityextra, vulnerabilityvalidation, portsnumber)
					VALUES
					('%s', '%s', '%s', '%s', 0, '%s')
					""" % (tooloutputnumber, hostnumber, name, code, portsnumber)
				)
				vulnnumber = int(db.lastrowid)
				ids = vulnerability.findall('id')
				for id in ids:
					if id.text:
						refval = id.text
					else:
						refval = " "
					if id.attrib:
						if id.get('type') is not None:
							reftype = id.get('type')
						else:
							reftype = " "
					db.execute("""
						INSERT INTO refs (tooloutputnumber, hostnumber, vulnerabilitynumber, referencetype, referencevalue )
						VALUES
						('%s', '%s', '%s', '%s', '%s')
						""" % (tooloutputnumber, hostnumber, vulnnumber, reftype, refval)
						)
	return

#!/usr/bin/python
# parsenmap.py
#
# By Adrien de Beaupre adriendb@gmail.com | adrien@intru-shun.ca
# Copyright 2011 Intru-Shun.ca Inc. 
# v0.09
# 16 October 2011
#
# The current version of these scripts are at: http://dshield.handers.org/adebeaupre/ossams-parser.tgz
#
# Parses nmap XML output
# http://nmap.org/
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

# parsenmap function
def parsenmap(time, os, root, filetoread, db, dbconnection, projectname, projectid, separator):
	# Check to see if the document root is 'nmaprun', exit if it is not
	if root.tag:
		if root.tag != "nmaprun":
			print filetoread, "is not a nmap XML report file."
			return
	if root.attrib:
		rootattribs = root.attrib
	nmapfile = filetoread.split(separator)
	file = nmapfile[-1]
	filetime = time.ctime(os.path.getmtime(filetoread))
	timenow = time.ctime()
	db.execute("""
		INSERT INTO tooloutput (toolname, filename, OSSAMSVersion, filedate, tooldate, version, inputtimestamp, projectname, projectid)
			VALUES
			('nmap', '%s', 0.09, '%s', '%s', '%s', '%s', '%s', '%s')
		""" % (file, filetime, rootattribs['startstr'], rootattribs['version'], timenow, projectname, projectid)
		)
	tooloutputnumber = int(db.lastrowid)
	print "Processed report number:", tooloutputnumber
	scaninfo = root.find('scaninfo')
	if scaninfo is not None:
		if scaninfo.attrib:
			scaninfoattribs = scaninfo.attrib
			for scaninfoattrib in scaninfoattribs.keys():
				db.execute("""
					INSERT INTO configuration (tooloutputnumber, configurationtype, configurationoptionname, configurationoptionvalue)
					VALUES
					('%s', 'nmap', '%s', '%s')
					""" % (tooloutputnumber, scaninfoattrib, scaninfoattribs[scaninfoattrib])
					)
	hosts = root.findall('host')
	for host in hosts:
		statuselement = host.find('status')
		if statuselement is not None:
			if statuselement.attrib:
				statusattribs = statuselement.attrib
				if statusattribs['state'] == "up":
					recon = 1
					reconreason = statusattribs['reason']
				else:
					recon = 0
					reconreason = statusattribs['reason']
		addresses = host.findall('address')
		addressattribs = {"addrtype": " ", "ipv4": " ", "ipv6": " ", "mac": " ", "vendor": " "}
		ipv6 = " "
		ipv4 = " "
		mac = " "
		macvendor = " "
		for address in addresses:
			if address.attrib:
				addressattribs = address.attrib
				if addressattribs['addrtype'] == "ipv4":
					ipv4 = addressattribs['addr']
				if addressattribs['addrtype'] == "ipv6":
					ipv6 = addressattribs['addr']
				if addressattribs['addrtype'] == "mac":
					mac = addressattribs['addr']
				if 'vendor' in addressattribs:
					macvendor = addressattribs['vendor']
		hostnames = host.findall('hostnames/hostname')
		hostname = " "
		hostptr = " "
		for name in hostnames:
			if name.attrib:
				nameattribs = name.attrib
				if nameattribs['type'] == "user":
					hostname = nameattribs['name']
				if nameattribs['type'] == "PTR":
					hostptr = nameattribs['name']
		osclass = host.find('os/osclass')
		osclassattribs = {"osfamily": " ", "osgen": " "}
		osmatchattribs = {"name": " "}
		if osclass is not None:
			if osclass.attrib:
				osclassattribs = osclass.attrib
				if not 'osfamily' in osclassattribs:
					osclassattribs['osfamily'] = " "
				if not 'osgen' in osclassattribs:
					osclassattribs['osgen'] = " "
		osmatch = host.find('os/osmatch')
		if osmatch is not None:
			if osmatch.attrib:
				osmatchattribs = osmatch.attrib
				if not 'name' in osmatchattribs:
					osmatchattribs['name'] = " "
		db.execute("""
			INSERT INTO hosts (tooloutputnumber, ipv6, ipv4, macaddress, macvendor, hostname, hostptr, recon, reconreason, 
				hostcriticality, hostos, osgen, osfamily)
			VALUES
			(%s, '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', 0, '%s', '%s', '%s')
			""" % (tooloutputnumber, ipv6, ipv4, mac, macvendor, hostname, hostptr, recon, reconreason, osmatchattribs['name'], 
				osclassattribs['osgen'], osclassattribs['osfamily'])
			)
		hostnumber = int(db.lastrowid)
		print "Processed host:", hostnumber, "IPv4:", ipv4
		ports = host.findall('ports/port')
		for port in ports:
			serviceattribs = {"name": " ", "product": " ", "version": " ", "extrainfo": " ", "conf": " ", "method": " "}
			portstateattribs = {"state": " ", "reason": " ", "reason_ttl": " "}
			if port.attrib:
				portattribs = port.attrib
			portstate = port.find('state')
			if portstate is not None:
				if portstate.attrib:
					portstateattribs = portstate.attrib
			service = port.find('service')
			if service is not None:
				if service.attrib:
					serviceattribs = service.attrib
				if not 'product' in serviceattribs:
					serviceattribs['product'] = " "
				if not 'version' in serviceattribs:
					serviceattribs['version'] = " "
				if not 'method' in serviceattribs:
					serviceattribs['method'] = " "
			db.execute("""
				INSERT INTO ports (tooloutputnumber, hostnumber, protocol, portnumber, portstate, reason, portname, portbanner, portversion, method, confidence)
				VALUES
				('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')
				""" % (tooloutputnumber, hostnumber, portattribs['protocol'], portattribs['portid'], portstateattribs['state'], portstateattribs['reason'], 
							serviceattribs['name'], serviceattribs['product'], serviceattribs['version'], serviceattribs['method'], serviceattribs['conf'])
				)
			portsnumber = int(db.lastrowid)
			scripts = port.findall('script')
			for script in scripts:
				if script.attrib:
					scriptattribs = script.attrib
					db.execute("""
						INSERT INTO vulnerabilities (tooloutputnumber, hostnumber, vulnerabilityname, vulnerabilitydescription, vulnerabilityvalidation, portsnumber)
						VALUES
						('%s', '%s', '%s', '%s', 0, '%s')
						""" % (tooloutputnumber, hostnumber, scriptattribs['id'], dbconnection.escape_string(scriptattribs['output']), portsnumber)
					)
					vulnnumber = int(db.lastrowid)
		scripts = host.findall('hostscript/script')
		for script in scripts:
			if script.attrib:
				scriptattribs = script.attrib
				db.execute("""
					INSERT INTO vulnerabilities (tooloutputnumber, hostnumber, vulnerabilityname, vulnerabilitydescription, vulnerabilityvalidation)
					VALUES
					('%s', '%s', '%s', '%s', 0)
					""" % (tooloutputnumber, hostnumber, scriptattribs['id'], dbconnection.escape_string(scriptattribs['output']))
				)
				vulnnumber = int(db.lastrowid)


				
				
				
				


	return

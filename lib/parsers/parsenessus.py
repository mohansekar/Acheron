#!/usr/bin/python
# parsenessus.py
#
# By Adrien de Beaupre adriendb@gmail.com | adrien@intru-shun.ca
# Copyright 2011 Intru-Shun.ca Inc. 
# v0.09
# 16 October 2011
#
# The current version of these scripts are at: http://dshield.handers.org/adebeaupre/ossams-parser.tgz
# 
# Parses nessus v2 XML output
# http://nessus.org
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

# parsenessus function
def parsenessus(time, os, root, filetoread, db, dbconnection, projectname, projectid, separator):
	# Check to see if the document root is 'nessus', exit if it is not
	if root.tag != "NessusClientData_v2":
		print filetoread, "is not a nessus v2 XML report file."
		return
	nessusfile = filetoread.split(separator)
	file = nessusfile[-1]
	filetime = time.ctime(os.path.getmtime(filetoread))
	timenow = time.ctime()
	db.execute("""
		INSERT INTO tooloutput (toolname, filename, OSSAMSVersion, filedate, inputtimestamp, projectname, projectid)
			VALUES
			('nessus', '%s', 0.09, '%s', '%s', '%s', '%s')
		""" % (file, filetime, timenow, projectname, projectid)
		)
	tooloutputnumber = int(db.lastrowid)
	print "Processed nessus report number:", tooloutputnumber
	reporthosts = root.findall('Report/ReportHost')
	tagattribs = ['HOST_START', 'operating-system', 'mac-address', 'host-ip', 'host-fqdn', 'smb-login-used', 'local-checks-proto', 'ssh-auth-meth', 'ssh-login-used', 'HOST_END']
	found19506 = 0
	for reporthost in reporthosts:
		if reporthost.attrib:
			hostip = reporthost.get('name')
		hostname = " "
		hostproperties = {'HOST_START': ' ', 'operating-system': ' ', 'mac-address': ' ', 'host-ip': ' ', 'host-fqdn': ' ', 'smb-login-used': ' ', 'local-checks-proto': ' ', 
		'ssh-auth-meth': ' ', 'ssh-login-used': ' ', 'netbios-name': ' ', 'HOST_END': ' '}
		if reporthost.attrib:
			ip = reporthost.get('name')
		tags = reporthost.findall('HostProperties/tag')
		for tag in tags:
			if tag.attrib:
				hostproperties[tag.get('name')] = tag.text
		if hostproperties['host-ip'] != " ":
			hostip = hostproperties['host-ip']
		if hostproperties['netbios-name'] != " ":
			hostname = hostproperties['netbios-name']
		if hostproperties['host-fqdn'] != " ":
			hostname = hostproperties['host-fqdn']
		db.execute("""
			INSERT INTO hosts (tooloutputnumber, ipv4, macaddress, hostname, recon, hostcriticality, hostos)
			VALUES
			(%s, '%s', '%s', '%s', 1, 0, '%s')
			""" % (tooloutputnumber, hostip, hostproperties['mac-address'], hostname, hostproperties['operating-system'])
			)
		hostnumber = int(db.lastrowid)
		print "Processed host:", hostnumber, "IP:", hostip
		#, "Name: ", hostname
		vulns = ['solution', 'risk_factor', 'description', 'synopsis', 'plugin_output']
		refs = ['cvss_vector', 'bid', 'xref', 'see_also', 'cve', 'cvss_base_score']
		reportitems = reporthost.findall('ReportItem')
		for reportitem in reportitems:
			vulnproperties = {'solution': ' ', 'risk_factor': ' ', 'description': ' ', 'synopsis': ' ', 'plugin_output': ' '}
			if reportitem.attrib:
				portproperties = reportitem.attrib
			db.execute("""
				INSERT INTO ports (tooloutputnumber, hostnumber, protocol, portnumber, portstate, portname)
				VALUES
				('%s', '%s', '%s', '%s', 'open', '%s')
				""" % (tooloutputnumber, hostnumber, portproperties['protocol'], portproperties['port'], portproperties['svc_name'],)
				)
			portnumber = int(db.lastrowid)
			for vuln in vulns:
				vulnerability = reportitem.find(vuln)
				if vulnerability is not None:
					if vulnerability.text:
						vulnproperties[vuln] = vulnerability.text
			db.execute("""
			INSERT INTO vulnerabilities (tooloutputnumber, hostnumber, vulnerabilityid, vulnerabilityname, vulnerabilityrisk, vulnerabilityseverity, 
				vulnerabilitydescription, vulnerabilitysolution, vulnerabilityextra, vulnerabilityvalidation, portsnumber)
				VALUES
				('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', 0, '%s')
				""" % (tooloutputnumber, hostnumber, portproperties['pluginID'], dbconnection.escape_string(portproperties['pluginName']), vulnproperties['risk_factor'],
				portproperties['severity'], dbconnection.escape_string(vulnproperties['description']), dbconnection.escape_string(vulnproperties['solution']),
				dbconnection.escape_string(vulnproperties['plugin_output']), portnumber)
			)
			vulnnumber = int(db.lastrowid)
			if portproperties['pluginID'] == '19506' and found19506 == 0:
				found19506 = 1
				if vulnproperties['plugin_output'] == " ":
					scaninfo = vulnproperties['description']
				else:
					scaninfo = vulnproperties['plugin_output']
				count = 0
				scaninfonolines = scaninfo.replace('\n', " : ")
				scaninfosplit = scaninfonolines.split(' : ')
				for item in scaninfosplit:
					count += 1
					if 'Nessus version' in item:
						version = scaninfosplit[count]
					if 'Scanner IP' in item:
						scanner = scaninfosplit[count]
					if 'Scan Start Date' in item:
						tooldate = scaninfosplit[count]
				db.execute("update tooloutput set version = '%s', scanner = '%s', tooldate = '%s' where tooloutputnumber = '%s' " 
					% (version, scanner, tooldate,tooloutputnumber))
			for ref in refs:
				references = reportitem.findall(ref)
				for reference in references:
					if reference.text:
						db.execute("""
							INSERT INTO refs (tooloutputnumber, hostnumber, vulnerabilitynumber, referencetype, referencevalue )
							VALUES
							('%s', '%s', '%s', '%s', '%s')
							""" % (tooloutputnumber, hostnumber, vulnnumber, ref, reference.text)
							)
	policy = root.find('Policy')
	if policy is not None:
		policyname = policy.find('policyName')
		if policyname.text:
			policyoption= policyname.text
		else:
			policyoption= " "			
		policycomments = policy.find('policyComments')
		if policycomments.text:
			policyvalue= policycomments.text
		else:
			policyvalue= " "	
		db.execute("""
			INSERT INTO configuration (tooloutputnumber, configurationtype, configurationoptionname, configurationoptionvalue)
			VALUES
			('%s', 'policy', '%s', '%s')
				""" % (tooloutputnumber, policyoption, policyvalue)
			)
		serverprefs = policy.findall('Preferences/ServerPreferences/preference')
		for serverpref in serverprefs:
			name = serverpref.find('name')
			if name is not None:
				if name.text:
					prefname = name.text
				else:
					prefname = " "
			value = serverpref.find('value')
			if value is not None:
				if value.text:
					prefvalue = value.text
				else:
					prefvalue = " "
			db.execute("""
				INSERT INTO configuration (tooloutputnumber, configurationtype, configurationoptionname, configurationoptionvalue)
				VALUES
				('%s', 'serverpref', '%s', '%s')
					""" % (tooloutputnumber, prefname, prefvalue)
				)
				

	return

#!/usr/bin/python
# parsegrendel.py
#
# By Adrien de Beaupre adriendb@gmail.com | adrien@intru-shun.ca
# Copyright 2011 Intru-Shun.ca Inc. 
# v0.09
# 16 October 2011
#
# The current version of these scripts are at: http://dshield.handers.org/adebeaupre/ossams-parser.tgz
#
# Parses grendel HTML output
# http://grendel-scan.com/
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

# parsegrendel function
def parsegrendel(time, os, etree, filetoread, db, dbconnection, projectname, projectid, separator):
	parser = etree.HTMLParser()
	tree   = etree.parse(filetoread, parser)
	xslt_root = etree.XML('''\
	<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
	<!-- Copy the XML as is. -->
	<xsl:template match="@* | node()">
		<xsl:copy>
			<xsl:apply-templates select="@* | node()"/>
		</xsl:copy>
	</xsl:template>

	<xsl:template match="html">
	<report>
	<xsl:apply-templates/>
	</report>
	</xsl:template>

	<xsl:template match="b">
		<xsl:apply-templates/>
		<xsl:text></xsl:text>
	</xsl:template>

	<xsl:template match="br">
		<xsl:apply-templates/>
		<xsl:text></xsl:text>
	</xsl:template>

	<xsl:template match="a">
		<xsl:apply-templates/>
		<xsl:text></xsl:text>
	</xsl:template>

	<xsl:template match="table[@class='findingTable']">
	<finding>
	<xsl:apply-templates/>
	</finding>
	</xsl:template>

	<xsl:template match="td[@class='vulnerabilityTitle']">
	<vulnerability>
	<xsl:apply-templates/>
	</vulnerability>
	</xsl:template>

	<xsl:template match="td[@class='heading']">
	<vulntype>
	<xsl:apply-templates/>
	</vulntype>
	</xsl:template>

	<xsl:template match="td[@class='vulnerabilityText']">
	<vulntext>
	<xsl:apply-templates/>
	</vulntext>
	</xsl:template>

	<xsl:template match="style"/>

	<xsl:template match="body">
		<xsl:apply-templates/>
		<xsl:text></xsl:text>
	</xsl:template>

	<xsl:template match="div">
		<xsl:apply-templates/>
		<xsl:text> </xsl:text>
	</xsl:template>

	<xsl:template match="head">
		<xsl:apply-templates/>
		<xsl:text> </xsl:text>
	</xsl:template>

	<xsl:template match="tr">
		<xsl:apply-templates/>
		<xsl:text>
		</xsl:text>
	</xsl:template>

	<xsl:template match="td">
		<xsl:apply-templates/>
		<xsl:text> </xsl:text>
	</xsl:template>

	</xsl:stylesheet>''')

	transform = etree.XSLT(xslt_root)
	root = tree.getroot()
	result = transform(root)

	xslt_root2 = etree.XML('''\
	<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
	<!-- Copy the XML as is. -->
	<xsl:template match="@* | node()">
		<xsl:copy>
			<xsl:apply-templates select="@* | node()"/>
		</xsl:copy>
	</xsl:template>

	<xsl:template match="vulntext[preceding-sibling::vulntype[1][text()='Severity:']]">
		<severity><xsl:value-of select="." /></severity>
	</xsl:template>

	<xsl:template match="vulntext[preceding-sibling::vulntype[1][text()='URL:']]">
		<url><xsl:value-of select="." /></url>
	</xsl:template>

	<xsl:template match="vulntext[preceding-sibling::vulntype[1][text()='Description:']]">
		<description><xsl:value-of select="." /></description>
	</xsl:template>

	<xsl:template match="vulntext[preceding-sibling::vulntype[1][text()='Impact:']]">
		<impact><xsl:value-of select="." /></impact>
	</xsl:template>
	<xsl:template match="vulntext[preceding-sibling::vulntype[1][text()='Recommendations:']]">
		<recommedations><xsl:value-of select="." /></recommedations>
	</xsl:template>

	<xsl:template match="vulntype">
	</xsl:template>

	</xsl:stylesheet>''')

	transform2 = etree.XSLT(xslt_root2)
	root2 = result.getroot()
	result2 = transform2(root2)
	root = result2.getroot()
	# Check to see if the document root is 'report', exit if it is not
	if root.tag != "report":
		print filetoread, "is not a grendel HTML report file"
		return
	title = root.find('title')
	if title is not None:
		if title.text:
			titlevalue = title.text
			titlesplit = titlevalue.split(':',1)
			date = titlesplit[1]
	grendelfile = filetoread.split(separator)
	file = grendelfile[-1]
	filetime = time.ctime(os.path.getmtime(filetoread))
	timenow = time.ctime()
	db.execute("""
		INSERT INTO tooloutput (toolname, filename, OSSAMSVersion, filedate, tooldate, inputtimestamp, projectname, projectid)
			VALUES
			('grendel', '%s', 0.09, '%s', '%s', '%s', '%s', '%s')
		""" % (file, filetime, date, timenow, projectname, projectid)
		)
	tooloutputnumber = int(db.lastrowid)
	db.execute("""
		INSERT INTO hosts (tooloutputnumber, recon, hostcriticality)
		VALUES
		('%s', 1 ,0)
		""" % (tooloutputnumber)
		)
	hostnumber = int(db.lastrowid)
	print "Processed grendel report number:", tooloutputnumber
	vulnelements = ['vulnerability', 'severity', 'url', 'description', 'impact', 'recommedations']
	vulnvalues = {'vulnerability': " ", 'severity': " ", 'url': " ", 'description': " ", 'impact': " ", 'recommedations': " "}
	findings = root.findall('table/finding')
	for finding in findings:
		for element in vulnelements:
			node = finding.find(element)
			if node is not None:
				if node.text:
					vulnvalues[element] = node.text
		description = vulnvalues['description'].encode('utf-8','ignore')
		impact = vulnvalues['impact'].encode('utf-8','ignore')
		db.execute("""
		INSERT INTO vulnerabilities (tooloutputnumber, hostnumber, vulnerabilityvalidation, vulnerabilityname, 
			vulnerabilityrisk, vulnerabilitydescription, vulnerabilitysolution, vulnerabilityuri, vulnerabilitydetails)
			VALUES
			('%s', '%s', 0, '%s', '%s', '%s', '%s', '%s', '%s')
			""" % (tooloutputnumber, hostnumber, vulnvalues['vulnerability'], vulnvalues['severity'], dbconnection.escape_string(description), 
				dbconnection.escape_string(vulnvalues['recommedations']), dbconnection.escape_string(vulnvalues['url']), dbconnection.escape_string(impact))
			)
		vulnnumber = int(db.lastrowid)
	return

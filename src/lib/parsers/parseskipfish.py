#!/usr/bin/python
# parseskipfish.py
#
# By Adrien de Beaupre adriendb@gmail.com | adrien@intru-shun.ca
# Copyright 2011 Intru-Shun.ca Inc. 
# v0.09
# 16 October 2011
#
# The current version of these scripts are at: http://dshield.handers.org/adebeaupre/ossams-parser.tgz
#
# Parses skipfish HTML and JSON output
# http://code.google.com/p/skipfish/
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

"""
Napping of tool field to OSSAMS database field:
tool field:		database field:
sf_version		tooloutput.version
scan_date		tooloutput.tooldate
severity		vulnerabilities.severity
type			vulnerabilities.vulnerabilityid
name			vulnerabilities.vulnerabilityname
request			vulnerabilities.httprequest
response		vulnerabilities.httpresponse
url 			vulnerabilities.vulnerabilityuri
extra			vulnerabilities.vulnerabilityextra

"""

# parseskipfish function
def parseskipfish(time, os, etree, sys, filetoread, db, dbconnection, projectname, projectid, separator):
	parser = etree.HTMLParser()
	newsamples = ""
	newsummary = ""
	counter = 0
	descriptions = ""
	directory = ""
	skipfishfile = filetoread.split(separator)
	file = skipfishfile[-1]
	filetime = time.ctime(os.path.getmtime(filetoread))
	timenow = time.ctime()
	skipfishfile.pop()
	for item in skipfishfile:
		directory = directory  + item + separator
	samplesfilein = directory + "samples.js"
	summaryfilein = directory + "summary.js"
	samplesfileout = directory + "skipfishsamples.py"
	summaryfileout = directory + "skipfishsummary.py"
	descfileout = directory + "skipfishdesc.py"
	if os.path.isfile(samplesfilein):
		sampleshandle = open(samplesfilein, 'r')
		for line in sampleshandle:
			newsamples = newsamples + line.replace('var ','')
		samplesfilehandle = open(samplesfileout, 'w')
		samplesfilehandle.write(newsamples)
		samplesfilehandle.close()
	else:
		print "Could not locate the skipfish samples.js file in: ", directory
		return
	if os.path.isfile(summaryfilein):
		summaryhandle = open(summaryfilein, 'r')
		for line in summaryhandle:
			newsummary = newsummary + line.replace('var ','')
		summaryfilehandle = open(summaryfileout, 'w')
		summaryfilehandle.write(newsummary)
		summaryfilehandle.close()
	else:
		print "Could not locate the skipfish summary.js file in: ", directory
		return
	if os.path.isfile(filetoread):
		tree   = etree.parse(filetoread, parser)
		root = tree.getroot()
		# Check to see if the document root is 'html', exit if it is not
		if root.tag:
			if root.tag != "html":
				print filetoread, "is not an skipfish HTML report file"
				return
		javascripts = root.findall('head/script')
		for javascript in javascripts:
			if javascript.text:
				contents = javascript.text
				splitcontents = contents.split('\n')
				for iterator in splitcontents:
					if 'var issue_desc' in iterator:
						firstcounter = counter
					if 'Simple HTML' in iterator:
						secondcounter = counter
					counter+=1
				for i in range(firstcounter, secondcounter):
					if 'var' in splitcontents[i]:
						descriptions = descriptions + splitcontents[i].replace('var ','')
					else:
						descriptions = descriptions + splitcontents[i]
				descfilehandle = open(descfileout, 'w')
				descfilehandle.write(descriptions)
				descfilehandle.close()
				sys.path.append(directory)
				from skipfishdesc import issue_desc
				from skipfishsamples import issue_samples
				import skipfishsummary 
				db.execute("""
					INSERT INTO tooloutput (toolname, filename, OSSAMSVersion, filedate, version, inputtimestamp, 
						tooldate, projectname, projectid)
						VALUES
						('skipfish', '%s', 0.09, '%s', '%s', '%s', '%s', '%s', '%s')
					""" % (file, filetime, skipfishsummary.sf_version, timenow, skipfishsummary.scan_date, projectname, projectid)
					)
				tooloutputnumber = int(db.lastrowid)
				print "Processed skipfish report number:", tooloutputnumber
				db.execute("""
					INSERT INTO hosts (tooloutputnumber, recon, hostcriticality)
					VALUES
					('%s', '1', '0')
					""" % (tooloutputnumber)
					)
				hostnumber = int(db.lastrowid)
				for issue in range(len(issue_samples)):
					issuedict = issue_samples[issue]
					typenum = issuedict['type']
					samplelist = issuedict['samples']
					for sample in range(len(samplelist)):
						sampledict = samplelist[sample]
						if sampledict['dir'] != '':
							directory = directory + sampledict['dir'].replace('/', separator)
							requestfile = directory + '\\request.dat'
							if os.path.isfile(requestfile):
								requestfilehandle = open(requestfile, 'r')
								request = requestfilehandle.read()
								requestfilehandle.close()
							else:
								request = ""
							responsefile = directory + separator + 'response.dat'
							if os.path.isfile(responsefile):
								responsefilehandle = open(responsefile, 'r')
								response = responsefilehandle.read()
								responsefilehandle.close()
							else:
								response = ""
						db.execute("""
						INSERT INTO vulnerabilities (tooloutputnumber, hostnumber, vulnerabilityid, vulnerabilityseverity, vulnerabilityname, 
							vulnerabilityextra, vulnerabilityuri, httprequest, httpresponse, vulnerabilityvalidation)
						VALUES
						('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', 0)
						""" % (tooloutputnumber, hostnumber, typenum, issuedict['severity'], dbconnection.escape_string(issue_desc[str(typenum)]), 
								dbconnection.escape_string(sampledict['extra']), dbconnection.escape_string(sampledict['url']), 
								dbconnection.escape_string(request), dbconnection.escape_string(response))
						)
						vulnnumber = int(db.lastrowid)
	else:
		print "Could not locate the skipfish index.html file"
	return



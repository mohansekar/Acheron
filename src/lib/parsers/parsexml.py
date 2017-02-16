#!/usr/bin/python
# parsexml.py
#
# By Adrien de Beaupre adriendb@gmail.com | adrien@intru-shun.ca
# Copyright 2011 Intru-Shun.ca Inc. 
# v0.09
# 16 October 2011
#
# The current version of these scripts are at: http://dshield.handers.org/adebeaupre/ossams-parser.tgz
#
# Parses XML output
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

from lxml import etree
# parsexml function
def parsexml(filetoread):
	try:
		# Parse the XML file
		tree = etree.parse(filetoread) 
		# Assign it to a variable as root
		root = tree.getroot()
		parsed = 'true'
	# What to do if the file does not parse
	except Exception, inst:
		print "\nError:"
		print "XML ElementTree parsing error opening %s: %s" % (filetoread, inst)
		print
		root = ""
		parsed = 'false'
		return (root, parsed)
	return (root, parsed)
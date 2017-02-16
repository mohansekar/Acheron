#!/usr/bin/python
# ossams-parser.py
#
# By Adrien de Beaupre adriendb@gmail.com | adrien@intru-shun.ca
# Copyright 2011 Intru-Shun.ca Inc. 
# v0.09
# 16 October 2011
#
# The current version of these scripts are at: http://dshield.handers.org/adebeaupre/ossams-parser.tgz
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

# sys provides system-specific parameters and functions
import sys
# os provides miscellaneous operating system interfaces
import os
# MySQLdb provides MySQL support for Python, database connectivity
import MySQLdb
# fnmatch provides Unix filename pattern matching
import fnmatch
# ConfigParser is a configuration file parser
from ConfigParser import SafeConfigParser 
# ElementTree provides the ElementTree XML API, parses XML
#from xml.etree.ElementTree import parse
# HTMLParser, not certain if I'm using this yet. Might choose a different HTML parser 
#import HTMLParser
# time provides time access and conversions
import time
# platform provides access to underlying platform data
import platform
# lxml XML toolkit is a Pythonic binding for the C libraries libxml2 and libxslt
# lxml provides XML and HTML parsing
# Will attempt to import elementree from lxml first, then from
# other standard locations on various versions of Python
try:
  from lxml import etree
  #print("running with lxml.etree")
except ImportError:
  try:
    # Python 2.5
    import xml.etree.cElementTree as etree
    #print("running with cElementTree on Python 2.5+")
  except ImportError:
    try:
      # Python 2.5
      import xml.etree.ElementTree as etree
      #print("running with ElementTree on Python 2.5+")
    except ImportError:
      try:
        # normal cElementTree install
        import cElementTree as etree
        #print("running with cElementTree")
      except ImportError:
        try:
          # normal ElementTree install
          import elementtree.ElementTree as etree
          #print("running with ElementTree")
        except ImportError:
          sys.exit("Failed to import ElementTree")

# If the platform we are running on is Windows we need \ for directory path.
if sys.platform == "win32":
	# Double backslash as the first escapes the second. 
	separator = "\\"
# Otherwise we are probably using Linux, Unix, OS X. Use / for directories.
else:
	separator = "/"

# Append the parsers directory to the Python modules path to import them
sys.path.append('.' + separator + 'parsers')

# Main function
def main(argv):
	# Print out the tool version and blurb. 
	print """
ossams-parser.py http://www.ossams.com
Parses security tool output and imports the data to a database, 
by Adrien de Beaupre. Version 0.09, 16 October 2011, Copyright Intru-Shun.ca Inc. 2011.
Usage: ossams-parser.py configfile.conf (default is ossams.conf) 
	"""
	# Declare some variables
	global db
	global dbconnection
	global projectname
	global projectid
	# Listing of currently supported tools:
	toollist = ['acunetix', 'burp', 'grendel' ,'nessus', 'netsparker', 'nexposec', 'nikto', 'nmap', 
		'ratproxy', 'retinac', 'skipfish', 'sslscan', 'w3af', 'wapiti', 'watcher','websecurify', 'zap']
	# If there is a program calling argument it should be the conf file to use. 
	if len(sys.argv) == 2: 
		configurationfile = sys.argv[1]
	else:
		#Otherwise use the default configuration file ossams.conf
		configurationfile = 'ossams.conf'
	# Check to see if the conf file exists.
	if os.path.isfile(configurationfile):
		# Use ConfigParser to grab the configuration file options.
		confparser = SafeConfigParser()
		# Read the configuration file
		confparser.read(configurationfile)
		if confparser.has_section('mysql'):
			# Grab the MySQL database connection options
			if confparser.has_option('mysql', 'username'):
				dbuser = confparser.get('mysql', 'username')
			else:
				# Use a default if not in the conf file
				dbuser = 'root'
			if confparser.has_option('mysql', 'password'):
				dbpasswd = confparser.get('mysql', 'password')
			else:
				# Use a default if not in the conf file
				dbpasswd = 'password'
			if confparser.has_option('mysql', 'host'):
				dbhost = confparser.get('mysql', 'host')
			else:
				# Use a default if not in the conf file
				dbhost = 'localhost'
			if confparser.has_option('mysql', 'port'):
				dbport = confparser.getint('mysql', 'port')
			else:
				# Use a default if not in the conf file
				dbport = '3306'
			if confparser.has_option('project', 'database'):
				dbname = confparser.get('project', 'database')
			else:
				# Use a default if not in the conf file
				dbname = 'ossams'
		else:
			# If we don't have MySQL parameters to use exit. 
			print "The configuration file does not have the required mysql section values"
			sys.exit(1)
		# Get the conf file parameters for parsing
		if confparser.has_option('files', 'directory'):
			filedirectory = confparser.get('files', 'directory')
		if confparser.has_option('files', 'file'):
			filetoread = confparser.get('files', 'file')
		if confparser.has_option('files', 'list'):
			filelist = confparser.get('files', 'list')
		if confparser.has_option('files', 'extension'):
			extension = confparser.get('files', 'extension')
		else:
			# Use a default if not in the conf file
			extension = 'xml'
		if confparser.has_option('project', 'projectid'):
			projectid = confparser.get('project', 'projectid')
		else:
			# Use a default if not in the conf file
			projectid = "None"
		if confparser.has_option('project', 'projectname'):
			projectname = confparser.get('project', 'projectname')	
		else:
			# Use a default if not in the conf file
			projectname = "None"
		if confparser.has_option('project', 'domain'):
			domain = confparser.get('project', 'domain')	
		else:
			# Use a default if not in the conf file
			domain = "default"
	else:
		# Exit with a message if the configuration file isn't there. 
		sys.exit("The configuration file does not appear to exist")
	# Use 'try' to catch database connection exceptions
	try:
		# Connect to the database
		dbconnection = MySQLdb.connect(host = dbhost, port = dbport, user = dbuser, passwd = dbpasswd)
		# db is the database connection instance
		db = dbconnection.cursor()
		# Use the OSSAMS database, or the one from the conf file
		db.execute("use %s;" % (dbname))
	# If the database connection fails print an error and exit. 
	except MySQLdb.Error, e:
		print "Error %d: %s" % (e.args[0], e.args[1])
		sys.exit (1)
	# Grab the tool from the conf file
	if confparser.has_section('tool'):
		if confparser.has_option('tool', 'tool'):
			global tool
			tool = confparser.get('tool', 'tool')
		else:
			print "The configuration file does not have a 'tool' specified"
			sys.exit(1)
		if tool not in toollist:
			print "The tool you have specified is not in the list of parsers"
			sys.exit(1)
	# If we have a file to read, go parse it
	if confparser.has_section('files'):
		if confparser.has_option('files', 'extension'):
			extension = confparser.get('files', 'extension')
			if confparser.has_option('files', 'directory'):
				filedirectory = confparser.get('files', 'directory')
				listdir(filedirectory, extension)
		if confparser.has_option('files', 'file'):
			filetoread = confparser.get('files', 'file')
			readfile(filetoread)
		if confparser.has_option('files', 'list'):
			filelist = confparser.get('files', 'list')
			readfilelist(filelist)
	else:
		print "The configuration file does not have a file specified to parse"
		sys.exit(1)
	# Close the database connections. 
	dbconnection.commit()
	db.close ()
	dbconnection.close ()
	# Out of here. 
	print
	print "Success!"
	return	
	
def readfile(filetoread):
	# Variable for the XML file to open is filetoread
	# Check to see if it is a file
	if os.path.isfile(filetoread):
		print "Parsing file:\t", filetoread
	else:
		print "The following file does not exist:", filetoread
		return
	from parsexml import parsexml
	# Go run the module for the tool selected. 
	if tool == 'nikto':
		# nikto parsing module
		from parsenikto import parsenikto
		(root,parsed) = parsexml(filetoread)
		if parsed == 'true':
			results = parsenikto(time, os, root, filetoread, db, dbconnection, projectname, projectid, separator)
	elif tool == 'nexposec':
		# parsenexposec parsing module
		from parsenexposecommunity import parsenexposec
		(root,parsed) = parsexml(filetoread)
		if parsed == 'true':
			results = parsenexposec(time, os, root, filetoread, db, dbconnection, projectname, projectid, separator)
	elif tool == 'ratproxy':
		# parseratproxy parsing module
		from parseratproxy import parseratproxy
		results = parseratproxy(time, os, etree, filetoread, db, dbconnection, projectname, projectid, separator)
	elif tool == 'wapiti':
		# parsewapiti parsing module
		from parsewapiti import parsewapiti
		(root,parsed) = parsexml(filetoread)
		if parsed == 'true':
			results = parsewapiti(time, os, root, filetoread, db, dbconnection, projectname, projectid, separator)
	elif tool == 'sslscan':
		# sslscan parsing module
		from parsesslscan import parsesslscan
		(root,parsed) = parsexml(filetoread)
		if parsed == 'true':
			results = parsesslscan(time, os, root, filetoread, db, dbconnection, projectname, projectid, separator)
	elif tool == 'retinac':
		# retina community parsing module
		from parseretinac import parseretinac
		(root,parsed) = parsexml(filetoread)
		if parsed == 'true':
			results = parseretinac(time, os, root, filetoread, db, dbconnection, projectname, projectid, separator)
	elif tool == 'nessus':
		# nessus parsing module
		from parsenessus import parsenessus
		(root,parsed) = parsexml(filetoread)
		if parsed == 'true':
			results = parsenessus(time, os, root, filetoread, db, dbconnection, projectname, projectid, separator)
	elif tool == 'watcher':
		# watcher parsing module
		from parsewatcher import parsewatcher
		(root,parsed) = parsexml(filetoread)
		if parsed == 'true':
			results = parsewatcher(time, os, root, filetoread, db, dbconnection, projectname, projectid, separator)
	elif tool == 'zap':
		# zap parsing module
		from parsezap import parsezap
		(root,parsed) = parsexml(filetoread)
		if parsed == 'true':
			results = parsezap(time, os, root, filetoread, db, dbconnection, projectname, projectid, separator)
	elif tool == 'w3af':
		# w3af parsing module
		from parsew3af import parsew3af
		(root,parsed) = parsexml(filetoread)
		if parsed == 'true':
			results = parsew3af(time, os, root, filetoread, db, dbconnection, projectname, projectid, separator)
	elif tool == 'nmap':
		# nmap parsing module
		from parsenmap import parsenmap
		(root,parsed) = parsexml(filetoread)
		if parsed == 'true':
			results = parsenmap(time, os, root, filetoread, db, dbconnection, projectname, projectid, separator)
	elif tool == 'burp':
		# burp parsing module
		from parseburp import parseburp
		(root,parsed) = parsexml(filetoread)
		if parsed == 'true':
			results = parseburp(time, os, root, filetoread, db, dbconnection, projectname, projectid, separator)
	elif tool == 'acunetix':
		# acunetix parsing module
		from parseacunetix import parseacunetix
		(root,parsed) = parsexml(filetoread)
		if parsed == 'true':
			results = parseacunetix(time, os, root, filetoread, db, dbconnection, projectname, projectid, separator)
	elif tool == 'netsparker':
		# netsparker parsing module
		from parsenetsparker import parsenetsparker
		(root,parsed) = parsexml(filetoread)
		if parsed == 'true':
			results = parsenetsparker(time, os, root, filetoread, db, dbconnection, projectname, projectid, separator)
	elif tool == 'websecurify':
		# websecurify parsing module
		from parsewebsecurify import parsewebsecurify
		(root,parsed) = parsexml(filetoread)
		if parsed == 'true':
			results = parsewebsecurify(time, os, root, filetoread, db, dbconnection, projectname, projectid, separator)
	elif tool == 'skipfish':
		# skipfish parsing module
		from parseskipfish import parseskipfish
		# Note that the skipfish parser requires lxml, not just elementtree.
		results = parseskipfish(time, os, etree, sys, filetoread, db, dbconnection, projectname, projectid, separator)
	elif tool == 'grendel':
		# grendel parsing module
		from parsegrendel import parsegrendel
		# Note that the Grendel Scan parser requires lxml, not just elementtree.
		results = parsegrendel(time, os, etree, filetoread, db, dbconnection, projectname, projectid, separator)
	else:
		# If an unsupported tool is selected return, should never get here. 
		print "Bad tool choice cuz we ain't got no parser fer it, and you shouldn't see this error anyways."
	return

# listdir function. Lists a directory contents, by file extension (typically XML)
def listdir(directory, extension): 
	# Check to see if the directory exists
	if os.path.isdir(directory):
		# Add splat to the directory listing
		extension = '*.' + extension
		# Process each file in the dirctory
		for file in os.listdir(directory):
			# Match the filename and extension
			if fnmatch.fnmatch(file, extension):
				filewithpath = directory + separator + file
				# Process each file with the readfile module. 
				readfile(filewithpath)
	else:
		# If the directory isn't there, return. 
		print "Directory: \'" + directory + "\' does not exist"
	return

# readfilelist module. Reads a file and parses each file name within it. 
def readfilelist(filelist):
	# Check to see if the file exists.
	if os.path.isfile(filelist):
		# Open up the file
		fileslist = open(filelist)
		# Grab the whole file as an array (may abend on a long list)
		wholefile = fileslist.readlines()
		# Iterate through each line
		for file in wholefile:
			# Get rid of whitespace
			filestripped = file.strip()
			# Go process each file
			readfile(filestripped)
	else:
		# If the file list isn't there return. 
		print "The listing file does not exist:", filelist
		return
	return

# If we were called as a program, go execute the main function. 
if __name__ == "__main__":
	main(sys.argv[1:])

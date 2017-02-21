
<img align="right" src="https://github.com/Acheron-VAF/Acheron/blob/master/src/gui/public/img/logo.png" height="150px" width="150px">

# Acheron (In Development)

[![Platform](https://img.shields.io/badge/Platform-WIndows%20%7C%20Linux%20%7C%20OSX-green.svg)]
[![License](https://img.shields.io/badge/License-MIT-green.svg)]
[![Version](https://img.shields.io/badge/Version-0.01-green.svg)]
[![Code](https://img.shields.io/badge/Code-Python%20%7C%20Javascript%20%7C%20ReactJS%20%7C%20MySQL%20%7C%20Electron%20%7C%20JSON-green.svg)]
[![Gem Version](http://img.shields.io/gem/v/suchgem.svg)]
[![License](http://img.shields.io/:license-mit-blue.svg)]
[![Badges](http://img.shields.io/:badges-7/7-ff6799.svg)]


[![Supported OS](https://img.shields.io/badge/Supported%20OS-Linux-yellow.svg) ![License](https://img.shields.io/badge/license-GPLv3-blue.svg) ![CORE](https://img.shields.io/badge/core-1.0.0.1-green.svg)![Build](https://img.shields.io/badge/BUILD-0068-red.svg)![Modules](https://img.shields.io/badge/modules-37-green.svg) ![Python](https://img.shields.io/badge/Python-2.7-green.svg) [![Build Status](https://travis-ci.org/PowerScript/KatanaFramework.svg?branch=master)](https://travis-ci.org/PowerScript/KatanaFramework)

Acheron is a RESTful vulnerability assessment and management framework built around search and dedicated to terminal extensibility. The framework was designed operating system agnostic and supports all major CPU architectures as well. The tool is built around a phased approach to vulnerability assessment that ensures quality by enforcing simplicity and enhancing productivity through search.

## Acheron Performs 5 Primary Functions:
 1. **Collection & Normalization of Vulnerability Data**
  - Supports many data types including: Nessus, Acunetix, Grendel, Burp, Nmap, Nikto, Nexpose, Zap, Retina, and More
  - Input threat models, intelligence, and risks
 2. **Search**
  - Acheron is built around search in order to inform and enhance rapid data analysis
  - Your own personal Google to empower Prioritization, Triage, Remediation, and Reporting
 3. **Automate & Analyze**
  - Incorporate authorized system/software inventories and watch them update based on real world data
  - Automated corelation of vulnerability data to organization specific threats
 4. **Data Management**
  - Track, categorize, and remediate vulnerabilities
  - Triage and assign risk ratings
 5. **Terminal Extensibility**
  - All data managed by Acheron can be accessed directly from the command line through both Bash and PowerShell
  - This enables rapid remediation opportunity and infinite yet simplistic extensibility


## Methodology
Acheron follows the Vulnerability Assessment Framework and associated tactics, techniques, and procedures. See [Vulnerability Assessment Framework](https://github.com/Acheron-VAF/Vulnerability-Assessment-Framework)

* 01 | Engagement Planning
* 02 | Threat Modeling
* 03 | Discovery
* 04 | Vulnerability Scanning
* 05 | Validation
* 06 | Remediation
* 07 | Reporting


## Development

* Acheron Tech Stack
 * Python Parsers
 * MySQL Backend Database
 * Electron App GUI
  * Javascript
  * ReactJS
  * JSON Configuration Files
  
* Building the GUI
 * Install npm
 * cd to gui/
 * run: npm install webpack
 * run: npm install -g electron
 * run: webpack
 * run: electron .
 * GUI should popup
  
Binary distributions available: [exe](https://github.com/Acheron-VAF/Acheron-Dist)



##Project Architecture
Acheron supports many OS and CPU builds via system agnostic design choices; however, it must be built to accomodate each. This (the main project archive) contains binary distributions for all major OS/CPU builds. It also contains all src/dev files.

This design was chosen so that anyone can download the main archive and use the tool. For leaner, OS Specific builds, see the Binary Distribution Repository: [dist](https://github.com/Acheron-VAF/Acheron-Dist)

For a lightweght src only build, download the src branch.


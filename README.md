
<img align="right" src="https://github.com/Acheron-VAF/Acheron/blob/master/gui/public/img/logo.png" height="150px" width="150px">

# Acheron

The Open Source Security Assessment Management System (OSSAMS) will be presented, which is a framework for the automation, data collection, analysis, and reporting in penetration testing and vulnerability assessment efforts. OSSAMS is written in Python and allows for the processing of tool results, parsing and normalizing the data, extraction of meaningful information via query, and more effective analysis.

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


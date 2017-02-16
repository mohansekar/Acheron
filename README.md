
<img align="right" src="https://github.com/Acheron-VAF/Acheron/blob/master/gui/public/img/logo.png" height="150px" width="150px">

# Acheron (In Development)

Acheron is a RESTful vulnerability assessment and management framework built around search and dedicated to terminal extensibility. The framework was designed operating system agnostic and supports all major CPU architectures as well. The tool is built around a phased approach to vulnerability assessment that ensures quality by enforcing simplicity and enhancing productivity through search.

Acheron Performs 5 Primary Functions:
 1. **Normalization of Vulnerability Data**
  - Supports many data types including: Nessus, Acunetix, Grendel, Burp, Nmap, Nikto, Nexpose, Zap, Retina, and More
  - Input threat models, intelligence, and risks
 2. **Search**
  - Acheron is built around search in order to inform and enhance rapid data analysis
  - Your own personal Google to empower Prioritization, Triage, Remediation, and Reporting
 3. **Automation**
  - Incorporate authorized system/software inventories and watch them update based on real world data
  - Automated corelation of vulnerability data to organization specific threats
 4. **Data Management**
  - Track, categorize, and remediate vulnerabilities
  - Triage and assign risk ratings
 5. **Terminal Extensibility**
  - All data managed by Acheron can be accessed directly from the command line through both Bash and PowerShell
  - This enables rapid remediation opportunity and infinite yet simplistic extensibility


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

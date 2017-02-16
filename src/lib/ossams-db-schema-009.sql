/*   

ossams-db-schema.sql - database schema file for ossams-Parser.py 
Parses security tool output and imports the data to a database, 
by Adrien de Beaupre. Version 0.09, 16 October 2011, Copyright Intru-Shun.ca Inc. 2011.

	This file is part of the ossams-parser.

    The ossams-parser is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    The ossams-parser is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with the ossams-parser.  If not, see <http://www.gnu.org/licenses/>.
*/


SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='TRADITIONAL';

CREATE SCHEMA IF NOT EXISTS `ossams` ;
USE `ossams` ;

-- -----------------------------------------------------
-- Table `ossams`.`tooloutput`
-- -----------------------------------------------------
CREATE  TABLE IF NOT EXISTS `ossams`.`tooloutput` (
  `tooloutputnumber` INT NOT NULL AUTO_INCREMENT COMMENT 'Primary Key' ,
  `projectname` TEXT NULL COMMENT 'Project Name - Name of the Client or project. User input for this field, but this is required.' ,
  `projectid` TEXT NULL COMMENT 'Project ID - Client, project, or scan number. User input for this field, but this is required.' ,
  `toolname` TEXT NOT NULL COMMENT 'Name of the tool that created the output.  This should be a drop down list and not manually entered.  This must match to a parsing type.' ,
  `filename` TEXT NOT NULL COMMENT 'Name of the file you input.' ,
  `filedate` TEXT NULL COMMENT 'Timestamp from the input file' ,
  `tooldate` TEXT NULL COMMENT 'Timestamp in the input file from the tool' , 
  `version` TEXT NULL COMMENT 'version of the scan tool' ,
  `ossamsversion` TEXT NOT NULL COMMENT 'schema version' ,
  `scanner` TEXT NULL COMMENT 'Scanner IP or name' ,
  `inputtimestamp` TEXT NULL COMMENT 'Timestamp for input datafile into database.' ,
  PRIMARY KEY (`tooloutputnumber`) )
ENGINE = InnoDB
COMMENT = 'Each tool will create an output file, typically either text ' /* comment truncated */ ;


-- -----------------------------------------------------
-- Table `ossams`.`hosts`
-- -----------------------------------------------------
CREATE  TABLE IF NOT EXISTS `ossams`.`hosts` (
  `hostnumber` INT NOT NULL AUTO_INCREMENT COMMENT 'Primary Key\nIndex is based on this column and tool-output_tool-output-number' ,
  `tooloutputnumber` INT NOT NULL ,
  `hostproperty` TEXT NULL COMMENT 'This is a miscellaneous property' ,
  `hostvalue` TEXT NULL COMMENT 'A host value specified by the hostproperty' ,
  `ipv4` TEXT NULL COMMENT 'The IPv4 address of the host or target. This can be an FQDN also.' ,
  `ipv6` TEXT NULL COMMENT 'The IPv6 address of the host or target. This can be an FQDN also.' ,
  `hostname` TEXT NULL COMMENT 'The hostname or FQDN.' ,
  `hostptr` TEXT NULL COMMENT 'The reverse DNS name.' ,
  `whois` TEXT NULL COMMENT 'The IP whois data.' ,
  `recon` BINARY NOT NULL ,
  `reconreason` TEXT NULL ,
  `hostcriticality` INT NULL ,
  `macaddress` TEXT NULL ,
  `macvendor` TEXT NULL ,
  `hostnotes` TEXT NULL ,
  `hostos` TEXT NULL ,
  `osgen` TEXT NULL ,
  `osfamily` TEXT NULL ,
  PRIMARY KEY (`hostnumber`))
ENGINE = InnoDB, 
COMMENT = 'This table contains information about hosts or IP addresses ' /* comment truncated */ ;


-- -----------------------------------------------------
-- Table `ossams`.`configuration`
-- -----------------------------------------------------
CREATE  TABLE IF NOT EXISTS `ossams`.`configuration` (
  `configurationnumber` INT NOT NULL AUTO_INCREMENT COMMENT 'primary Key' ,
  `tooloutputnumber` INT NOT NULL ,
  `configurationtype` TEXT NULL COMMENT 'Configuration type or parameter field name.  example would Nessus reports table' ,
  `configurationoptionname` TEXT NULL COMMENT 'Configuration type or parameter function or setting name.' ,
  `configurationoptionvalue` LONGTEXT NULL COMMENT 'Configuration type or parameter function or setting value.' ,
  PRIMARY KEY (`configurationnumber`))
ENGINE = InnoDB, 
COMMENT = 'This table contains the tool configuration options. Examples' /* comment truncated */ ;


-- -----------------------------------------------------
-- Table `ossams`.`ports`
-- -----------------------------------------------------
CREATE  TABLE IF NOT EXISTS `ossams`.`ports` (
  `portsnumber` INT NOT NULL AUTO_INCREMENT COMMENT 'primary key' ,
  `tooloutputnumber` INT NOT NULL ,
  `hostnumber` INT NOT NULL ,
  `protocol` TEXT NOT NULL COMMENT 'protocol name of the protocol discovered' ,
  `portnumber` TEXT NOT NULL COMMENT 'the number from 1-65535' ,
  `portstate` TEXT NOT NULL COMMENT 'the state the procotol is in' ,
  `reason` TEXT NULL COMMENT 'why the port state is known' ,
  `portbanner` TEXT NULL COMMENT 'the banner of the port, if any' ,
  `portversion` TEXT NULL COMMENT 'the version of the banner or service, if any' ,
  `portname` TEXT NULL COMMENT 'the port name' ,
  `service` TEXT NULL COMMENT 'the service, if known' ,
  `method` TEXT NULL COMMENT 'method used to determine the service' ,
  `confidence` TEXT NULL COMMENT 'confidence in the service guess' ,  
  `portattribute` TEXT NULL ,
  `portvalue` TEXT NULL ,
  PRIMARY KEY (`portsnumber`))
ENGINE = InnoDB, 
COMMENT = 'This table contains information about ports (open or closed)' /* comment truncated */ ;

-- -----------------------------------------------------
-- Table `ossams`.`vulnerabilities`
-- -----------------------------------------------------
CREATE  TABLE IF NOT EXISTS `ossams`.`vulnerabilities` (
  `vulnerabilitynumber` INT NOT NULL AUTO_INCREMENT COMMENT 'primary key' ,
  `tooloutputnumber` INT NOT NULL ,
  `hostnumber` INT NOT NULL ,
  `portsnumber` INT NULL ,
  `vulnerabilityid` TEXT NULL COMMENT 'Tool identifier or pluginid for the vulnerability' ,
  `vulnerabilityseverity` TEXT NULL COMMENT 'Severity numeric value' ,
  `vulnerabilityrisk` TEXT NULL COMMENT 'Risk description' ,
  `vulnerabilityconf` TEXT NULL COMMENT 'Confidence in the finding, sometimes comes from the tool' ,
  `falsepositive` BINARY NULL DEFAULT 0 COMMENT 'If the finding is a false positive' ,
  `vulnerabilityname` TEXT NULL COMMENT 'The name of the Vulnerability' ,
  `vulnerabilitydescription` TEXT NULL COMMENT 'The description of the vulnerability' ,
  `vulnerabilitysolution` TEXT NULL COMMENT 'The solution to correct the vulnerability.' ,
  `vulnerabilitydetails` TEXT NULL COMMENT 'The details of the vulnerability' ,
  `vulnerabilityextra` TEXT NULL COMMENT 'Additional information about the vulnerability such as tool output' ,
  `vulnerabilityvalidation` BINARY NOT NULL DEFAULT 0 COMMENT 'Has the vulnerability been validated' ,
  `vulnerabilitynotes` TEXT NULL COMMENT 'Notes to be entered during the assessment about the vulnerability' ,
  `vulnerabilityattribute` TEXT NULL ,
  `vulnerabilityvalue` TEXT NULL ,
  `vulnerabilityuri` TEXT NULL COMMENT 'URI of the vulnerability, if web based' ,
  `httprequest` LONGTEXT NULL ,
  `httpcookie` TEXT NULL ,
  `httpmethod` TEXT NULL ,
  `httpresponsecode` TEXT NULL ,
  `httpresponse` LONGTEXT NULL ,
  `httpparam` TEXT NULL ,
  PRIMARY KEY (`vulnerabilitynumber`))
ENGINE = InnoDB, 
COMMENT = 'Each host may have none, one, or muliple vulnerabilities ass' /* comment truncated */ ;


-- -----------------------------------------------------
-- Table `ossams`.`refs`
-- -----------------------------------------------------
CREATE  TABLE IF NOT EXISTS `ossams`.`refs` (
  `referencenumber` INT NOT NULL AUTO_INCREMENT COMMENT 'primary key' ,
  `tooloutputnumber` INT NOT NULL ,
  `hostnumber` INT NOT NULL ,
  `vulnerabilitynumber` INT NOT NULL ,
  `referencetype` TEXT NOT NULL COMMENT 'type value of the reference' ,
  `referencevalue` TEXT NOT NULL COMMENT 'value of the reference' ,
  PRIMARY KEY (`referencenumber`))
ENGINE = InnoDB, 
COMMENT = 'Each vulnerability may have none, one, or more references as' /* comment truncated */ ;



SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;

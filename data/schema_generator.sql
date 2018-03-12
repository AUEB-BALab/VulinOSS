-- DROP SCHEMA IF EXISTS `vulinoss`;
-- CREATE SCHEMA `vulinoss`;

DROP TABLE IF EXISTS `vulinoss`.`code_metrics`;
DROP TABLE IF EXISTS `vulinoss`.`programming_languages`;
DROP TABLE IF EXISTS `vulinoss`.`vulnerable_cases`;
DROP TABLE IF EXISTS `vulinoss`.`project_releases`;
DROP TABLE IF EXISTS `vulinoss`.`continuous_integration_providers`;
DROP TABLE IF EXISTS `vulinoss`.`project`;
DROP TABLE IF EXISTS `vulinoss`.`software_categories`;
DROP TABLE IF EXISTS `vulinoss`.`cve`;
DROP TABLE IF EXISTS `vulinoss`.`cwe`;

-- CWE Research Concepts version --
CREATE TABLE `vulinoss`.`cwe` 
(
	`cwe` VARCHAR(20) NOT NULL,
    `name` VARCHAR(1000),
    `description` VARCHAR(1000),
    
    PRIMARY KEY(`cwe`)
);

CREATE TABLE `vulinoss`.`cve` 
(
	`id` VARCHAR(50) NOT NULL,
    `description` VARCHAR(2048),
    `published_date` DATE,
    `modified_date` DATE,
    -- CWE id --
    `cwe` VARCHAR(20),
    -- CVSS metricsV2 --
    `cvssV2_vector_string` VARCHAR(100),
    `cvssV2_access_vector` VARCHAR(50),
    `cvssV2_access_complexity` VARCHAR(20),
    `cvssV2_authentication` VARCHAR(50),
	`cvssV2_confidentiality_impact` VARCHAR(50),
	`cvssV2_integrity_impact` VARCHAR(50),
    `cvssV2_availability_impact` VARCHAR(50),
    `cvssV2_base_score` REAL,
    `severity` VARCHAR(20),
    `exploitation_score` REAL,
    `impact_score` REAL,
    `obtain_all_privilege` BOOLEAN,
    `obtain_user_privilege` BOOLEAN,
    `obtain_other_privilege` BOOLEAN,
    `user_interaction_required` BOOLEAN,
    
    PRIMARY KEY(`id`),
	CONSTRAINT `CWE id does not exist` FOREIGN KEY (`cwe`) REFERENCES `vulinoss`.`cwe` (`cwe`) ON DELETE CASCADE
    );

CREATE TABLE `vulinoss`.`software_categories`
(
	`id` INT(5) NOT NULL,
    `scname` VARCHAR(100),
    `description` VARCHAR(1000),
    
    PRIMARY KEY(`id`)
);

CREATE TABLE `vulinoss`.`project`
(
	`id` INT(20) NOT NULL,
    `pvendor` VARCHAR(100) NOT NULL,
    `pname` VARCHAR(100) NOT NULL,
    `software_type` INT(5),
    `website` VARCHAR(300),
    `repo_url` VARCHAR(1000),
    `repo_type` VARCHAR(3),
    `has_version_mapping` BOOLEAN,
    
    PRIMARY KEY(`id`),
	CONSTRAINT `Software category id does not exist` FOREIGN KEY (`software_type`) REFERENCES `vulinoss`.`software_categories` (`id`) ON DELETE CASCADE
);

CREATE TABLE `vulinoss`.`continuous_integration_providers`
(
	`id` INT(5) NOT NULL,
	`ciname` VARCHAR(50) NOT NULL,

    PRIMARY KEY(`id`)
);

CREATE TABLE `vulinoss`.`project_releases`
(
	`id` INT(20) NOT NULL,
	`version_name` VARCHAR(100) NOT NULL,
    `pid` INT(20) NOT NULL,
    `version_reference` VARCHAR(1000),
    `continuous_integration` INT(5) DEFAULT NULL,
    
    PRIMARY KEY(`id`),
	CONSTRAINT `Project id does not exist` FOREIGN KEY (`pid`) REFERENCES `vulinoss`.`project` (`id`) ON DELETE CASCADE,
    CONSTRAINT `CI id does not exist` FOREIGN KEY (`continuous_integration`) REFERENCES `vulinoss`.`continuous_integration_providers` (`id`)

);

CREATE TABLE `vulinoss`.`vulnerable_cases`
(
	`cve` VARCHAR(50) NOT NULL,
    `prid` INT(20) NOT NULL,
    
    PRIMARY KEY(`cve`,`prid`),
	CONSTRAINT `Project release id does not exist` FOREIGN KEY (`prid`) REFERENCES `project_releases` (`id`) ON DELETE CASCADE,
    CONSTRAINT `CVE  does not exist` FOREIGN KEY (`cve`) REFERENCES `vulinoss`.`cve` (`id`) ON DELETE CASCADE
);

CREATE TABLE `vulinoss`.`programming_languages`
(
	`id` int(5) NOT NULL,
    `plname` VARCHAR(50) NOT NULL,
    
    PRIMARY KEY(`id`)
);

CREATE TABLE `vulinoss`.`code_metrics`
(
	`prid` int(20) NOT NULL,
    `language_id` INT(5) NOT NULL,
    `size` int(20) NOT NULL,
    `blank` int(20) NOT NULL,
    `comment` int(20) NOT NULL,
    `loc` int(20) NOT NULL,
    `testing_size` int(20),
    `testing_blank` int(20),
    `testing_comment` int(20),
    `testing_loc` int(20),
    
    PRIMARY KEY(`prid`,`language_id`),
	CONSTRAINT `prid (Project release id) does not exist` FOREIGN KEY (`prid`) REFERENCES `project_releases` (`id`) ON DELETE CASCADE,
	CONSTRAINT `language_id (Language id) does not exist` FOREIGN KEY (`language_id`) REFERENCES `vulinoss`.`programming_languages` (`id`) ON DELETE CASCADE

);

-- Insert statements for populating the CWE table --
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-1004","Sensitive Cookie Without HttpOnly Flag","The software uses a cookie to store sensitive information");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-1007","Insufficient Visual Distinction of Homoglyphs Presented to User","The software displays information or identifiers to a user");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-102","Struts: Duplicate Validation Forms","The application uses multiple validation forms with the same name");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-1021","Improper Restriction of Rendered UI Layers or Frames","The web application does not restrict or incorrectly restricts frame objects or UI layers that belong to another application or domain");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-1022","Improper Restriction of Cross-Origin Permission to window.opener.location","The web application does not restrict or incorrectly restricts modification of its window opener objects location property by an external application from a different origin.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-103","Struts: Incomplete validate() Method Definition","The application has a validator form that either does not define a validate() method");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-104","Struts: Form Bean Does Not Extend Validation Class","If a form bean does not extend an ActionForm subclass of the Validator framework");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-105","Struts: Form Field Without Validator","The application has a form field that is not validated by a corresponding validation form");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-106","Struts: Plug-in Framework not in Use","When an application does not use an input validation framework such as the Struts Validator");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-107","Struts: Unused Validation Form","An unused validation form indicates that validation logic is not up-to-date.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-108","Struts: Unvalidated Action Form","Every Action Form must have a corresponding validation form.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-109","Struts: Validator Turned Off","Automatic filtering via a Struts bean has been turned off");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-11","ASP.NET Misconfiguration: Creating Debug Binary","Debugging messages help attackers learn about the system and plan a form of attack.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-110","Struts: Validator Without Form Field","Validation fields that do not appear in forms they are associated with indicate that the validation logic is out of date.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-111","Direct Use of Unsafe JNI","When a Java application uses the Java Native Interface (JNI) to call code written in another programming language");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-112","Missing XML Validation","The software accepts XML from an untrusted source but does not validate the XML against the proper schema.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-113","Improper Neutralization of CRLF Sequences in HTTP Headers (HTTP Response Splitting)","The software receives data from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-114","Process Control","Executing commands or loading libraries from an untrusted source or in an untrusted environment can cause an application to execute malicious commands (and payloads) on behalf of an attacker.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-115","Misinterpretation of Input","The software misinterprets an input");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-116","Improper Encoding or Escaping of Output","The software prepares a structured message for communication with another component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-117","Improper Output Neutralization for Logs","The software does not neutralize or incorrectly neutralizes output that is written to logs.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-118","Incorrect Access of Indexable Resource (Range Error)","The software does not restrict or incorrectly restricts operations within the boundaries of a resource that is accessed using an index or pointer");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-119","Improper Restriction of Operations within the Bounds of a Memory Buffer","The software performs operations on a memory buffer");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-12","ASP.NET Misconfiguration: Missing Custom Error Page","An ASP .NET application must enable custom error pages in order to prevent attackers from mining information from the frameworks built-in responses.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-120","Buffer Copy without Checking Size of Input (Classic Buffer Overflow)","The program copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-121","Stack-based Buffer Overflow","A stack-based buffer overflow condition is a condition where the buffer being overwritten is allocated on the stack (i.e.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-122","Heap-based Buffer Overflow","A heap overflow condition is a buffer overflow");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-123","Write-what-where Condition","Any condition where the attacker has the ability to write an arbitrary value to an arbitrary location");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-124","Buffer Underwrite (Buffer Underflow)","The software writes to a buffer using an index or pointer that references a memory location prior to the beginning of the buffer.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-125","Out-of-bounds Read","The software reads data past the end");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-126","Buffer Over-read","The software reads from a buffer using buffer access mechanisms such as indexes or pointers that reference memory locations after the targeted buffer.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-127","Buffer Under-read","The software reads from a buffer using buffer access mechanisms such as indexes or pointers that reference memory locations prior to the targeted buffer.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-128","Wrap-around Error","Wrap around errors occur whenever a value is incremented past the maximum value for its type and therefore wraps around to a very small");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-129","Improper Validation of Array Index","The product uses untrusted input when calculating or using an array index");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-13","ASP.NET Misconfiguration: Password in Configuration File","Storing a plaintext password in a configuration file allows anyone who can read the file access to the password-protected resource making them an easy target for attackers.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-130","Improper Handling of Length Parameter Inconsistency ","The software parses a formatted message or structure");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-131","Incorrect Calculation of Buffer Size","The software does not correctly calculate the size to be used when allocating a buffer");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-134","Use of Externally-Controlled Format String","The software uses a function that accepts a format string as an argument");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-135","Incorrect Calculation of Multi-Byte String Length","The software does not correctly calculate the length of strings that can contain wide or multi-byte characters.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-138","Improper Neutralization of Special Elements","The software receives input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-14","Compiler Removal of Code to Clear Buffers","Sensitive memory is cleared according to the source code");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-140","Improper Neutralization of Delimiters","The software does not neutralize or incorrectly neutralizes delimiters.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-141","Improper Neutralization of Parameter/Argument Delimiters","The software receives input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-142","Improper Neutralization of Value Delimiters","The software receives input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-143","Improper Neutralization of Record Delimiters","The software receives input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-144","Improper Neutralization of Line Delimiters","The software receives input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-145","Improper Neutralization of Section Delimiters","The software receives input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-146","Improper Neutralization of Expression/Command Delimiters","The software receives input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-147","Improper Neutralization of Input Terminators","The software receives input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-148","Improper Neutralization of Input Leaders","The application does not properly handle when a leading character or sequence (leader) is missing or malformed");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-149","Improper Neutralization of Quoting Syntax","Quotes injected into an application can be used to compromise a system. As data are parsed");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-15","External Control of System or Configuration Setting","One or more system settings or configuration elements can be externally controlled by a user.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-150","Improper Neutralization of Escape","Variant");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-151","Improper Neutralization of Comment Delimiters","The software receives input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-152","Improper Neutralization of Macro Symbols","The software receives input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-153","Improper Neutralization of Substitution Characters","The software receives input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-154","Improper Neutralization of Variable Name Delimiters","The software receives input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-155","Improper Neutralization of Wildcards or Matching Symbols","The software receives input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-156","Improper Neutralization of Whitespace","The software receives input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-157","Failure to Sanitize Paired Delimiters","The software does not properly handle the characters that are used to mark the beginning and ending of a group of entities");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-158","Improper Neutralization of Null Byte or NUL Character","The software receives input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-159","Failure to Sanitize Special Element","Weaknesses in this attack-focused category do not properly filter and interpret special elements in user-controlled input which could cause adverse effect on the software behavior and integrity.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-160","Improper Neutralization of Leading Special Elements","The software receives input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-161","Improper Neutralization of Multiple Leading Special Elements","The software receives input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-162","Improper Neutralization of Trailing Special Elements","The software receives input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-163","Improper Neutralization of Multiple Trailing Special Elements","The software receives input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-164","Improper Neutralization of Internal Special Elements","The software receives input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-165","Improper Neutralization of Multiple Internal Special Elements","The software receives input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-166","Improper Handling of Missing Special Element","The software receives input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-167","Improper Handling of Additional Special Element","The software receives input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-168","Improper Handling of Inconsistent Special Elements","The software does not handle when an inconsistency exists between two or more special characters or reserved words.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-170","Improper Null Termination","The software does not terminate or incorrectly terminates a string or array with a null character or equivalent terminator.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-172","Encoding Error","The software does not properly encode or decode the data");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-173","Improper Handling of Alternate Encoding","The software does not properly handle when an input uses an alternate encoding that is valid for the control sphere to which the input is being sent.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-174","Double Decoding of the Same Data","The software decodes the same input twice");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-175","Improper Handling of Mixed Encoding","The software does not properly handle when the same input uses several different (mixed) encodings.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-176","Improper Handling of Unicode Encoding","The software does not properly handle when an input contains Unicode encoding.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-177","Improper Handling of URL Encoding (Hex Encoding)","The software does not properly handle when all or part of an input has been URL encoded.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-178","Improper Handling of Case Sensitivity","The software does not properly account for differences in case sensitivity when accessing or determining the properties of a resource");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-179","Incorrect Behavior Order: Early Validation","The software validates input before applying protection mechanisms that modify the input");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-180","Incorrect Behavior Order: Validate Before Canonicalize","The software validates input before it is canonicalized");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-181","Incorrect Behavior Order: Validate Before Filter","The software validates data before it has been filtered");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-182","Collapse of Data into Unsafe Value","The software filters data in a way that causes it to be reduced or collapsed into an unsafe value that violates an expected security property.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-183","Permissive Whitelist","An application uses a whitelist of acceptable values");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-184","Incomplete Blacklist","An application uses a blacklist of prohibited values");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-185","Incorrect Regular Expression","The software specifies a regular expression in a way that causes data to be improperly matched or compared.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-186","Overly Restrictive Regular Expression","A regular expression is overly restrictive");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-187","Partial Comparison","The software performs a comparison that only examines a portion of a factor before determining whether there is a match");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-188","Reliance on Data/Memory Layout","The software makes invalid assumptions about how protocol data or memory is organized at a lower level");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-190","Integer Overflow or Wraparound","The software performs a calculation that can produce an integer overflow or wraparound");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-191","Integer Underflow (Wrap or Wraparound)","The product subtracts one value from another");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-192","Integer Coercion Error","Integer coercion refers to a set of flaws pertaining to the type casting");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-193","Off-by-one Error","A product calculates or uses an incorrect maximum or minimum value that is 1 more");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-194","Unexpected Sign Extension","The software performs an operation on a number that causes it to be sign extended when it is transformed into a larger data type. When the original number is negative");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-195","Signed to Unsigned Conversion Error","The software uses a signed primitive and performs a cast to an unsigned primitive");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-196","Unsigned to Signed Conversion Error","The software uses an unsigned primitive and performs a cast to a signed primitive");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-197","Numeric Truncation Error","Truncation errors occur when a primitive is cast to a primitive of a smaller size and data is lost in the conversion.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-198","Use of Incorrect Byte Ordering","The software receives input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-20","Improper Input Validation","The product does not validate or incorrectly validates input that can affect the control flow or data flow of a program.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-200","Information Exposure","An information exposure is the intentional or unintentional disclosure of information to an actor that is not explicitly authorized to have access to that information.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-201","Information Exposure Through Sent Data","The accidental exposure of sensitive information through sent data refers to the transmission of data which are either sensitive in and of itself or useful in the further exploitation of the system through standard data channels.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-202","Exposure of Sensitive Data Through Data Queries","When trying to keep information confidential");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-203","Information Exposure Through Discrepancy","The product behaves differently or sends different responses in a way that exposes security-relevant information about the state of the product");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-204","Response Discrepancy Information Exposure","The software provides different responses to incoming requests in a way that allows an actor to determine system state information that is outside of that actors control sphere.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-205","Information Exposure Through Behavioral Discrepancy","The products actions indicate important differences based on (1) the internal state of the product or (2) differences from other products in the same class.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-206","Information Exposure of Internal State Through Behavioral Inconsistency","Two separate operations in a product cause the product to behave differently in a way that is observable to an attacker and reveals security-relevant information about the internal state of the product");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-207","Information Exposure Through an External Behavioral Inconsistency","The product behaves differently than other products like it");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-208","Information Exposure Through Timing Discrepancy","Two separate operations in a product require different amounts of time to complete");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-209","Information Exposure Through an Error Message","The software generates an error message that includes sensitive information about its environment");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-210","Information Exposure Through Self-generated Error Message","The software identifies an error condition and creates its own diagnostic or error messages that contain sensitive information.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-211","Information Exposure Through Externally-Generated Error Message","The software performs an operation that triggers an external diagnostic or error message that is not directly generated by the software");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-212","Improper Cross-boundary Removal of Sensitive Data","The software uses a resource that contains sensitive data");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-213","Intentional Information Exposure","A products design or configuration explicitly requires the publication of information that could be regarded as sensitive by an administrator.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-214","Information Exposure Through Process Environment","A process is invoked with sensitive arguments");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-215","Information Exposure Through Debug Information","The application contains debugging code that can expose sensitive information to untrusted parties.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-216","Containment Errors (Container Errors)","This tries to cover various problems in which improper data are included within a container.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-219","Sensitive Data Under Web Root","The application stores sensitive data under the web document root with insufficient access control");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-22","Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)","The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-220","Sensitive Data Under FTP Root","The application stores sensitive data under the FTP document root with insufficient access control");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-221","Information Loss or Omission","The software does not record");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-222","Truncation of Security-relevant Information","The application truncates the display");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-223","Omission of Security-relevant Information","The application does not record or display information that would be important for identifying the source or nature of an attack");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-224","Obscured Security-relevant Information by Alternate Name","The software records security-relevant information according to an alternate name of the affected entity");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-226","Sensitive Information Uncleared Before Release","The software does not fully clear previously used information in a data structure");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-228","Improper Handling of Syntactically Invalid Structure","The product does not handle or incorrectly handles input that is not syntactically well-formed with respect to the associated specification.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-229","Improper Handling of Values","The software does not properly handle when the expected number of values for parameters");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-23","Relative Path Traversal","The software uses external input to construct a pathname that should be within a restricted directory");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-230","Improper Handling of Missing Values","The software does not handle or incorrectly handles when a parameter");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-231","Improper Handling of Extra Values","The software does not handle or incorrectly handles when more values are provided than expected.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-232","Improper Handling of Undefined Values","The software does not handle or incorrectly handles when a value is not defined or supported for the associated parameter");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-233","Improper Handling of Parameters","The software does not properly handle when the expected number of parameters");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-234","Failure to Handle Missing Parameter","If too few arguments are sent to a function");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-235","Improper Handling of Extra Parameters","The software does not handle or incorrectly handles when the number of parameters");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-236","Improper Handling of Undefined Parameters","The software does not handle or incorrectly handles when a particular parameter");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-237","Improper Handling of Structural Elements","The software does not handle or incorrectly handles inputs that are related to complex structures.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-238","Improper Handling of Incomplete Structural Elements","The software does not handle or incorrectly handles when a particular structural element is not completely specified.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-239","Failure to Handle Incomplete Element","The software does not properly handle when a particular element is not completely specified.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-24","Path Traversal: ../filedir","The software uses external input to construct a pathname that should be within a restricted directory");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-240","Improper Handling of Inconsistent Structural Elements","The software does not handle or incorrectly handles when two or more structural elements should be consistent");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-241","Improper Handling of Unexpected Data Type","The software does not handle or incorrectly handles when a particular element is not the expected type");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-242","Use of Inherently Dangerous Function","The program calls a function that can never be guaranteed to work safely.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-243","Creation of chroot Jail Without Changing Working Directory","The program uses the chroot() system call to create a jail");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-244","Improper Clearing of Heap Memory Before Release (Heap Inspection)","Using realloc() to resize buffers that store sensitive information can leave the sensitive information exposed to attack");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-245","J2EE Bad Practices: Direct Management of Connections","The J2EE application directly manages connections");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-246","J2EE Bad Practices: Direct Use of Sockets","The J2EE application directly uses sockets instead of using framework method calls.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-248","Uncaught Exception","An exception is thrown from a function");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-25","Path Traversal: /../filedir","The software uses external input to construct a pathname that should be within a restricted directory");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-250","Execution with Unnecessary Privileges","The software performs an operation at a privilege level that is higher than the minimum level required");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-252","Unchecked Return Value","The software does not check the return value from a method or function");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-253","Incorrect Check of Function Return Value","The software incorrectly checks a return value from a function");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-256","Plaintext Storage of a Password","Storing a password in plaintext may result in a system compromise.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-257","Storing Passwords in a Recoverable Format","The storage of passwords in a recoverable format makes them subject to password reuse attacks by malicious users. In fact");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-258","Empty Password in Configuration File","Using an empty string as a password is insecure.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-259","Use of Hard-coded Password","The software contains a hard-coded password");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-26","Path Traversal: /dir/../filename","The software uses external input to construct a pathname that should be within a restricted directory");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-260","Password in Configuration File","The software stores a password in a configuration file that might be accessible to actors who do not know the password.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-261","Weak Cryptography for Passwords","Obscuring a password with a trivial encoding does not protect the password.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-262","Not Using Password Aging","If no mechanism is in place for managing password aging");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-263","Password Aging with Long Expiration","Allowing password aging to occur unchecked can result in the possibility of diminished password integrity.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-266","Incorrect Privilege Assignment","A product incorrectly assigns a privilege to a particular actor");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-267","Privilege Defined With Unsafe Actions","A particular privilege");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-268","Privilege Chaining","Two distinct privileges");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-269","Improper Privilege Management","The software does not properly assign");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-27","Path Traversal: dir/../../filename","The software uses external input to construct a pathname that should be within a restricted directory");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-270","Privilege Context Switching Error","The software does not properly manage privileges while it is switching between different contexts that have different privileges or spheres of control.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-271","Privilege Dropping / Lowering Errors","The software does not drop privileges before passing control of a resource to an actor that does not have those privileges.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-272","Least Privilege Violation","The elevated privilege level required to perform operations such as chroot() should be dropped immediately after the operation is performed.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-273","Improper Check for Dropped Privileges","The software attempts to drop privileges but does not check or incorrectly checks to see if the drop succeeded.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-274","Improper Handling of Insufficient Privileges","The software does not handle or incorrectly handles when it has insufficient privileges to perform an operation");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-276","Incorrect Default Permissions","The software");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-277","Insecure Inherited Permissions","A product defines a set of insecure permissions that are inherited by objects that are created by the program.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-278","Insecure Preserved Inherited Permissions","A product inherits a set of insecure permissions for an object");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-279","Incorrect Execution-Assigned Permissions","While it is executing");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-28","Path Traversal: ..filedir","The software uses external input to construct a pathname that should be within a restricted directory");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-280","Improper Handling of Insufficient Permissions or Privileges ","The application does not handle or incorrectly handles when it has insufficient privileges to access resources or functionality as specified by their permissions. This may cause it to follow unexpected code paths that may leave the application in an invalid state.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-281","Improper Preservation of Permissions","The software does not preserve permissions or incorrectly preserves permissions when copying");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-282","Improper Ownership Management","The software assigns the wrong ownership");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-283","Unverified Ownership","The software does not properly verify that a critical resource is owned by the proper entity.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-284","Improper Access Control","The software does not restrict or incorrectly restricts access to a resource from an unauthorized actor.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-285","Improper Authorization","The software does not perform or incorrectly performs an authorization check when an actor attempts to access a resource or perform an action.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-286","Incorrect User Management","The software does not properly manage a user within its environment.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-287","Improper Authentication","When an actor claims to have a given identity");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-288","Authentication Bypass Using an Alternate Path or Channel","A product requires authentication");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-289","Authentication Bypass by Alternate Name","The software performs authentication based on the name of a resource being accessed");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-29","Path Traversal: ..filename","The software uses external input to construct a pathname that should be within a restricted directory");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-290","Authentication Bypass by Spoofing","This attack-focused weakness is caused by improperly implemented authentication schemes that are subject to spoofing attacks.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-291","Reliance on IP Address for Authentication","The software uses an IP address for authentication.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-293","Using Referer Field for Authentication","The referer field in HTTP requests can be easily modified and");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-294","Authentication Bypass by Capture-replay","A capture-replay flaw exists when the design of the software makes it possible for a malicious user to sniff network traffic and bypass authentication by replaying it to the server in question to the same effect as the original message (or with minor changes).");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-295","Improper Certificate Validation","The software does not validate");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-296","Improper Following of a Certificates Chain of Trust","The software does not follow");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-297","Improper Validation of Certificate with Host Mismatch","The software communicates with a host that provides a certificate");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-298","Improper Validation of Certificate Expiration","A certificate expiration is not validated or is incorrectly validated");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-299","Improper Check for Certificate Revocation","The software does not check or incorrectly checks the revocation status of a certificate");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-30","Path Traversal: dir..filename","The software uses external input to construct a pathname that should be within a restricted directory");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-300","Channel Accessible by Non-Endpoint (Man-in-the-Middle)","The product does not adequately verify the identity of actors at both ends of a communication channel");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-301","Reflection Attack in an Authentication Protocol","Simple authentication protocols are subject to reflection attacks if a malicious user can use the target machine to impersonate a trusted user.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-302","Authentication Bypass by Assumed-Immutable Data","The authentication scheme or implementation uses key data elements that are assumed to be immutable");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-303","Incorrect Implementation of Authentication Algorithm","The requirements for the software dictate the use of an established authentication algorithm");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-304","Missing Critical Step in Authentication","The software implements an authentication technique");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-305","Authentication Bypass by Primary Weakness","The authentication algorithm is sound");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-306","Missing Authentication for Critical Function","The software does not perform any authentication for functionality that requires a provable user identity or consumes a significant amount of resources.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-307","Improper Restriction of Excessive Authentication Attempts","The software does not implement sufficient measures to prevent multiple failed authentication attempts within in a short time frame");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-308","Use of Single-factor Authentication","The use of single-factor authentication can lead to unnecessary risk of compromise when compared with the benefits of a dual-factor authentication scheme.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-309","Use of Password System for Primary Authentication","The use of password systems as the primary means of authentication may be subject to several flaws or shortcomings");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-31","Path Traversal: dir....filename","The software uses external input to construct a pathname that should be within a restricted directory");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-311","Missing Encryption of Sensitive Data","The software does not encrypt sensitive or critical information before storage or transmission.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-312","Cleartext Storage of Sensitive Information","The application stores sensitive information in cleartext within a resource that might be accessible to another control sphere.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-313","Cleartext Storage in a File or on Disk","The application stores sensitive information in cleartext in a file");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-314","Cleartext Storage in the Registry","The application stores sensitive information in cleartext in the registry.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-315","Cleartext Storage of Sensitive Information in a Cookie","The application stores sensitive information in cleartext in a cookie.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-316","Cleartext Storage of Sensitive Information in Memory","The application stores sensitive information in cleartext in memory.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-317","Cleartext Storage of Sensitive Information in GUI","The application stores sensitive information in cleartext within the GUI.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-318","Cleartext Storage of Sensitive Information in Executable","The application stores sensitive information in cleartext in an executable.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-319","Cleartext Transmission of Sensitive Information","The software transmits sensitive or security-critical data in cleartext in a communication channel that can be sniffed by unauthorized actors.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-32","Path Traversal: ... (Triple Dot)","The software uses external input to construct a pathname that should be within a restricted directory");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-321","Use of Hard-coded Cryptographic Key","The use of a hard-coded cryptographic key significantly increases the possibility that encrypted data may be recovered.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-322","Key Exchange without Entity Authentication","The software performs a key exchange with an actor without verifying the identity of that actor.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-323","Reusing a Nonce","Incomplete");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-324","Use of a Key Past its Expiration Date","The product uses a cryptographic key or password past its expiration date");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-325","Missing Required Cryptographic Step","The software does not implement a required step in a cryptographic algorithm");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-326","Inadequate Encryption Strength","The software stores or transmits sensitive data using an encryption scheme that is theoretically sound");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-327","Use of a Broken or Risky Cryptographic Algorithm","The use of a broken or risky cryptographic algorithm is an unnecessary risk that may result in the exposure of sensitive information.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-328","Reversible One-Way Hash","The product uses a hashing algorithm that produces a hash value that can be used to determine the original input");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-329","Not Using a Random IV with CBC Mode","Not using a random initialization Vector (IV) with Cipher Block Chaining (CBC) Mode causes algorithms to be susceptible to dictionary attacks.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-33","Path Traversal: .... (Multiple Dot)","The software uses external input to construct a pathname that should be within a restricted directory");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-330","Use of Insufficiently Random Values","The software may use insufficiently random numbers or values in a security context that depends on unpredictable numbers.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-331","Insufficient Entropy","The software uses an algorithm or scheme that produces insufficient entropy");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-332","Insufficient Entropy in PRNG","The lack of entropy available for");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-333","Improper Handling of Insufficient Entropy in TRNG","True random number generators (TRNG) generally have a limited source of entropy and therefore can fail or block.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-334","Small Space of Random Values","The number of possible random values is smaller than needed by the product");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-335","Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG)","The software uses a Pseudo-Random Number Generator (PRNG) that does not correctly manage seeds.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-336","Same Seed in Pseudo-Random Number Generator (PRNG)","A Pseudo-Random Number Generator (PRNG) uses the same seed each time the product is initialized.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-337","Predictable Seed in Pseudo-Random Number Generator (PRNG)","A Pseudo-Random Number Generator (PRNG) is initialized from a predictable seed");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-338","Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)","The product uses a Pseudo-Random Number Generator (PRNG) in a security context");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-339","Small Seed Space in PRNG","A PRNG uses a relatively small space of seeds.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-34","Path Traversal: ....//","The software uses external input to construct a pathname that should be within a restricted directory");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-340","Predictability Problems","Weaknesses in this category are related to schemes that generate numbers or identifiers that are more predictable than required by the application.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-341","Predictable from Observable State","A number or object is predictable based on observations that the attacker can make about the state of the system or network");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-342","Predictable Exact Value from Previous Values","An exact value or random number can be precisely predicted by observing previous values.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-343","Predictable Value Range from Previous Values","The softwares random number generator produces a series of values which");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-344","Use of Invariant Value in Dynamically Changing Context","The product uses a constant value");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-345","Insufficient Verification of Data Authenticity","The software does not sufficiently verify the origin or authenticity of data");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-346","Origin Validation Error","The software does not properly verify that the source of data or communication is valid.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-347","Improper Verification of Cryptographic Signature","The software does not verify");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-348","Use of Less Trusted Source","The software has two different sources of the same data or information");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-349","Acceptance of Extraneous Untrusted Data With Trusted Data","The software");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-35","Path Traversal: .../...//","The software uses external input to construct a pathname that should be within a restricted directory");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-350","Reliance on Reverse DNS Resolution for a Security-Critical Action","The software performs reverse DNS resolution on an IP address to obtain the hostname and make a security decision");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-351","Insufficient Type Distinction","The software does not properly distinguish between different types of elements in a way that leads to insecure behavior.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-352","Cross-Site Request Forgery (CSRF)","The web application does not");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-353","Missing Support for Integrity Check","The software uses a transmission protocol that does not include a mechanism for verifying the integrity of the data during transmission");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-354","Improper Validation of Integrity Check Value","The software does not validate or incorrectly validates the integrity check values or checksums of a message. This may prevent it from detecting if the data has been modified or corrupted in transmission.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-356","Product UI does not Warn User of Unsafe Actions","The softwares user interface does not warn the user before undertaking an unsafe action on behalf of that user. This makes it easier for attackers to trick users into inflicting damage to their system.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-357","Insufficient UI Warning of Dangerous Operations","The user interface provides a warning to a user regarding dangerous or sensitive operations");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-358","Improperly Implemented Security Check for Standard","The software does not implement or incorrectly implements one or more security-relevant checks as specified by the design of a standardized algorithm");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-359","Exposure of Private Information (Privacy Violation)","The software does not properly prevent private data (such as credit card numbers) from being accessed by actors who either (1) are not explicitly authorized to access the data or (2) do not have the implicit consent of the people to which the data is related.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-36","Absolute Path Traversal","The software uses external input to construct a pathname that should be within a restricted directory");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-360","Trust of System Event Data","Security based on event locations are insecure and can be spoofed.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-362","Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition)","The program contains a code sequence that can run concurrently with other code");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-363","Race Condition Enabling Link Following","The software checks the status of a file or directory before accessing it");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-364","Signal Handler Race Condition","The software uses a signal handler that introduces a race condition.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-365","Race Condition in Switch","The code contains a switch statement in which the switched variable can be modified while the switch is still executing");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-366","Race Condition within a Thread","If two threads of execution use a resource simultaneously");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-367","Time-of-check Time-of-use (TOCTOU) Race Condition","The software checks the state of a resource before using that resource");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-368","Context Switching Race Condition","A product performs a series of non-atomic actions to switch between contexts that cross privilege or other security boundaries");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-369","Divide By Zero","The product divides a value by zero.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-37","Path Traversal: /absolute/pathname/here","A software system that accepts input in the form of a slash absolute path (/absolute/pathname/here) without appropriate validation can allow an attacker to traverse the file system to unintended locations or access arbitrary files.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-370","Missing Check for Certificate Revocation after Initial Check","The software does not check the revocation status of a certificate after its initial revocation check");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-372","Incomplete Internal State Distinction","The software does not properly determine which state it is in");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-374","Passing Mutable Objects to an Untrusted Method","The program sends non-cloned mutable data as an argument to a method or function.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-375","Returning a Mutable Object to an Untrusted Caller","Sending non-cloned mutable data as a return value may result in that data being altered or deleted by the calling function.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-377","Insecure Temporary File","Creating and using insecure temporary files can leave application and system data vulnerable to attack.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-378","Creation of Temporary File With Insecure Permissions","Opening temporary files without appropriate measures or controls can leave the file");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-379","Creation of Temporary File in Directory with Incorrect Permissions","The software creates a temporary file in a directory whose permissions allow unintended actors to determine the files existence or otherwise access that file.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-38","Path Traversal: absolutepathnamehere","A software system that accepts input in the form of a backslash absolute path (absolutepathnamehere) without appropriate validation can allow an attacker to traverse the file system to unintended locations or access arbitrary files.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-382","J2EE Bad Practices: Use of System.exit()","A J2EE application uses System.exit()");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-383","J2EE Bad Practices: Direct Use of Threads","Thread management in a Web application is forbidden in some circumstances and is always highly error prone.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-384","Session Fixation","Authenticating a user");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-385","Covert Timing Channel","Covert timing channels convey information by modulating some aspect of system behavior over time");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-386","Symbolic Name not Mapping to Correct Object","A constant symbolic reference to an object is used");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-39","Path Traversal: C:dirname","An attacker can inject a drive letter or Windows volume letter (C:dirname) into a software system to potentially redirect access to an unintended location or arbitrary file.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-390","Detection of Error Condition Without Action","The software detects a specific error");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-391","Unchecked Error Condition","Ignoring exceptions and other error conditions may allow an attacker to induce unexpected behavior unnoticed.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-392","Missing Report of Error Condition","The software encounters an error but does not provide a status code or return value to indicate that an error has occurred.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-393","Return of Wrong Status Code","A function or operation returns an incorrect return value or status code that does not indicate an error");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-394","Unexpected Status Code or Return Value","The software does not properly check when a function or operation returns a value that is legitimate for the function");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-395","Use of NullPointerException Catch to Detect NULL Pointer Dereference","Catching NullPointerException should not be used as an alternative to programmatic checks to prevent dereferencing a null pointer.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-396","Declaration of Catch for Generic Exception","Catching overly broad exceptions promotes complex error handling code that is more likely to contain security vulnerabilities.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-397","Declaration of Throws for Generic Exception","Throwing overly broad exceptions promotes complex error handling code that is more likely to contain security vulnerabilities.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-40","Path Traversal: UNCsharename (Windows UNC Share)","An attacker can inject a Windows UNC share (UNCsharename) into a software system to potentially redirect access to an unintended location or arbitrary file.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-400","Uncontrolled Resource Consumption (Resource Exhaustion)","The software does not properly restrict the size or amount of resources that are requested or influenced by an actor");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-401","Improper Release of Memory Before Removing Last Reference (Memory Leak)","The software does not sufficiently track and release allocated memory after it has been used");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-402","Transmission of Private Resources into a New Sphere (Resource Leak)","The software makes resources available to untrusted parties when those resources are only intended to be accessed by the software.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-403","Exposure of File Descriptor to Unintended Control Sphere (File Descriptor Leak)","A process does not close sensitive file descriptors before invoking a child process");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-404","Improper Resource Shutdown or Release","The program does not release or incorrectly releases a resource before it is made available for re-use.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-405","Asymmetric Resource Consumption (Amplification)","Software that does not appropriately monitor or control resource consumption can lead to adverse system performance.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-406","Insufficient Control of Network Message Volume (Network Amplification)","The software does not sufficiently monitor or control transmitted network traffic volume");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-407","Algorithmic Complexity","An algorithm in a product has an inefficient worst-case computational complexity that may be detrimental to system performance and can be triggered by an attacker");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-408","Incorrect Behavior Order: Early Amplification","The software allows an entity to perform a legitimate but expensive operation before authentication or authorization has taken place.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-409","Improper Handling of Highly Compressed Data (Data Amplification)","The software does not handle or incorrectly handles a compressed input with a very high compression ratio that produces a large output.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-41","Improper Resolution of Path Equivalence","The system or application is vulnerable to file system contents disclosure through path equivalence. Path equivalence involves the use of special characters in file and directory names. The associated manipulations are intended to generate multiple names for the same object.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-410","Insufficient Resource Pool","The softwares resource pool is not large enough to handle peak demand");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-412","Unrestricted Externally Accessible Lock","The software properly checks for the existence of a lock");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-413","Improper Resource Locking","The software does not lock or does not correctly lock a resource when the software must have exclusive access to the resource.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-414","Missing Lock Check","A product does not check to see if a lock is present before performing sensitive operations on a resource.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-415","Double Free","The product calls free() twice on the same memory address");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-416","Use After Free","Referencing memory after it has been freed can cause a program to crash");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-419","Unprotected Primary Channel","The software uses a primary channel for administration or restricted functionality");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-42","Path Equivalence: filename. (Trailing Dot)","A software system that accepts path input in the form of trailing dot (filedir.) without appropriate validation can lead to ambiguous path resolution and allow an attacker to traverse the file system to unintended locations or access arbitrary files.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-420","Unprotected Alternate Channel","The software protects a primary channel");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-421","Race Condition During Access to Alternate Channel","The product opens an alternate channel to communicate with an authorized user");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-422","Unprotected Windows Messaging Channel (Shatter)","The software does not properly verify the source of a message in the Windows Messaging System while running at elevated privileges");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-424","Improper Protection of Alternate Path","The product does not sufficiently protect all possible paths that a user can take to access restricted functionality or resources.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-425","Direct Request (Forced Browsing)","The web application does not adequately enforce appropriate authorization on all restricted URLs");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-426","Untrusted Search Path","The application searches for critical resources using an externally-supplied search path that can point to resources that are not under the applications direct control.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-427","Uncontrolled Search Path Element","The product uses a fixed or controlled search path to find resources");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-428","Unquoted Search Path or Element","The product uses a search path that contains an unquoted element");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-43","Path Equivalence: filename.... (Multiple Trailing Dot)","A software system that accepts path input in the form of multiple trailing dot (filedir....) without appropriate validation can lead to ambiguous path resolution and allow an attacker to traverse the file system to unintended locations or access arbitrary files.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-430","Deployment of Wrong Handler","The wrong handler is assigned to process an object.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-431","Missing Handler","A handler is not available or implemented.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-432","Dangerous Signal Handler not Disabled During Sensitive Operations","The application uses a signal handler that shares state with other signal handlers");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-433","Unparsed Raw Web Content Delivery","The software stores raw content or supporting code under the web document root with an extension that is not specifically handled by the server.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-434","Unrestricted Upload of File with Dangerous Type","The software allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the products environment.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-435","Improper Interaction Between Multiple Entities","An interaction error occurs when two entities work correctly when running independently");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-436","Interpretation Conflict","Product A handles inputs or steps differently than Product B");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-437","Incomplete Model of Endpoint Features","A product acts as an intermediary or monitor between two or more endpoints");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-439","Behavioral Change in New Version or Environment","As behavior or functionality changes with a new version of A");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-44","Path Equivalence: file.name (Internal Dot)","A software system that accepts path input in the form of internal dot (file.ordir) without appropriate validation can lead to ambiguous path resolution and allow an attacker to traverse the file system to unintended locations or access arbitrary files.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-440","Expected Behavior Violation","A feature");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-441","Unintended Proxy or Intermediary (Confused Deputy)","The software receives a request");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-444","Inconsistent Interpretation of HTTP Requests (HTTP Request Smuggling)","When malformed or abnormal HTTP requests are interpreted by one or more entities in the data flow between the user and the web server");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-446","UI Discrepancy for Security Feature","The user interface does not correctly enable or configure a security feature");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-447","Unimplemented or Unsupported Feature in UI","A UI function for a security feature appears to be supported and gives feedback to the user that suggests that it is supported");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-448","Obsolete Feature in UI","A UI function is obsolete and the product does not warn the user.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-449","The UI Performs the Wrong Action","The UI performs the wrong action with respect to the users request.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-45","Path Equivalence: file...name (Multiple Internal Dot)","A software system that accepts path input in the form of multiple internal dot (file...dir) without appropriate validation can lead to ambiguous path resolution and allow an attacker to traverse the file system to unintended locations or access arbitrary files.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-450","Multiple Interpretations of UI Input","The UI has multiple interpretations of user input but does not prompt the user when it selects the less secure interpretation.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-451","User Interface (UI) Misrepresentation of Critical Information","The user interface (UI) does not properly represent critical information to the user");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-453","Insecure Default Variable Initialization","The software");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-454","External Initialization of Trusted Variables or Data Stores","The software initializes critical internal variables or data stores using inputs that can be modified by untrusted actors.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-455","Non-exit on Failed Initialization","The software does not exit or otherwise modify its operation when security-relevant errors occur during initialization");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-456","Missing Initialization of a Variable","The software does not initialize critical variables");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-457","Use of Uninitialized Variable","The code uses a variable that has not been initialized");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-459","Incomplete Cleanup","The software does not properly clean up and remove temporary or supporting resources after they have been used.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-46","Path Equivalence: filename  (Trailing Space)","A software system that accepts path input in the form of trailing space (filedir ) without appropriate validation can lead to ambiguous path resolution and allow an attacker to traverse the file system to unintended locations or access arbitrary files.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-460","Improper Cleanup on Thrown Exception","The product does not clean up its state or incorrectly cleans up its state when an exception is thrown");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-462","Duplicate Key in Associative List (Alist)","Duplicate keys in associative lists can lead to non-unique keys being mistaken for an error.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-463","Deletion of Data Structure Sentinel","The accidental deletion of a data-structure sentinel can cause serious programming logic problems.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-464","Addition of Data Structure Sentinel","The accidental addition of a data-structure sentinel can cause serious programming logic problems.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-466","Return of Pointer Value Outside of Expected Range","A function can return a pointer to memory that is outside of the buffer that the pointer is expected to reference.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-467","Use of sizeof() on a Pointer Type","The code calls sizeof() on a malloced pointer type");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-468","Incorrect Pointer Scaling","In C and C++");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-469","Use of Pointer Subtraction to Determine Size","The application subtracts one pointer from another in order to determine size");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-47","Path Equivalence:  filename (Leading Space)","A software system that accepts path input in the form of leading space ( filedir) without appropriate validation can lead to ambiguous path resolution and allow an attacker to traverse the file system to unintended locations or access arbitrary files.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-470","Use of Externally-Controlled Input to Select Classes or Code (Unsafe Reflection)","The application uses external input with reflection to select which classes or code to use");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-471","Modification of Assumed-Immutable Data (MAID)","The software does not properly protect an assumed-immutable element from being modified by an attacker.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-472","External Control of Assumed-Immutable Web Parameter","The web application does not sufficiently verify inputs that are assumed to be immutable but are actually externally controllable");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-473","PHP External Variable Modification","A PHP application does not properly protect against the modification of variables from external sources");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-474","Use of Function with Inconsistent Implementations","The code uses a function that has inconsistent implementations across operating systems and versions.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-475","Undefined Behavior for Input to API","The behavior of this function is undefined unless its control parameter is set to a specific value.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-476","NULL Pointer Dereference","A NULL pointer dereference occurs when the application dereferences a pointer that it expects to be valid");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-477","Use of Obsolete Function","The code uses deprecated or obsolete functions");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-478","Missing Default Case in Switch Statement","The code does not have a default case in a switch statement");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-479","Signal Handler Use of a Non-reentrant Function","The program defines a signal handler that calls a non-reentrant function.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-48","Path Equivalence: file name (Internal Whitespace)","A software system that accepts path input in the form of internal space (file(SPACE)name) without appropriate validation can lead to ambiguous path resolution and allow an attacker to traverse the file system to unintended locations or access arbitrary files.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-480","Use of Incorrect Operator","The programmer accidentally uses the wrong operator");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-481","Assigning instead of Comparing","The code uses an operator for assignment when the intention was to perform a comparison.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-482","Comparing instead of Assigning","The code uses an operator for comparison when the intention was to perform an assignment.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-483","Incorrect Block Delimitation","The code does not explicitly delimit a block that is intended to contain 2 or more statements");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-484","Omitted Break Statement in Switch","The program omits a break statement within a switch or similar construct");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-486","Comparison of Classes by Name","The program compares classes by name");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-487","Reliance on Package-level Scope","Java packages are not inherently closed; therefore");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-488","Exposure of Data Element to Wrong Session","The product does not sufficiently enforce boundaries between the states of different sessions");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-489","Leftover Debug Code","The application can be deployed with active debugging code that can create unintended entry points.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-49","Path Equivalence: filename/ (Trailing Slash)","A software system that accepts path input in the form of trailing slash (filedir/) without appropriate validation can lead to ambiguous path resolution and allow an attacker to traverse the file system to unintended locations or access arbitrary files.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-491","Public cloneable() Method Without Final (Object Hijack)","A class has a cloneable() method that is not declared final");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-492","Use of Inner Class Containing Sensitive Data","Inner classes are translated into classes that are accessible at package scope and may expose code that the programmer intended to keep private to attackers.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-493","Critical Public Variable Without Final Modifier","The product has a critical public variable that is not final");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-494","Download of Code Without Integrity Check","The product downloads source code or an executable from a remote location and executes the code without sufficiently verifying the origin and integrity of the code.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-495","Private Array-Typed Field Returned From A Public Method","The product has a method that is declared public");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-496","Public Data Assigned to Private Array-Typed Field","Assigning public data to a private array is equivalent to giving public access to the array.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-497","Exposure of System Data to an Unauthorized Control Sphere","Exposing system data or debugging information helps an adversary learn about the system and form an attack plan.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-498","Cloneable Class Containing Sensitive Information","The code contains a class with sensitive data");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-499","Serializable Class Containing Sensitive Data","The code contains a class with sensitive data");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-5","J2EE Misconfiguration: Data Transmission Without Encryption","Information sent over a network can be compromised while in transit. An attacker may be able to read or modify the contents if the data are sent in plaintext or are weakly encrypted.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-50","Path Equivalence: //multiple/leading/slash","A software system that accepts path input in the form of multiple leading slash (//multiple/leading/slash) without appropriate validation can lead to ambiguous path resolution and allow an attacker to traverse the file system to unintended locations or access arbitrary files.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-500","Public Static Field Not Marked Final","An object contains a public static field that is not marked final");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-501","Trust Boundary Violation","The product mixes trusted and untrusted data in the same data structure or structured message.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-502","Deserialization of Untrusted Data","The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-506","Embedded Malicious Code","The application contains code that appears to be malicious in nature.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-507","Trojan Horse","The software appears to contain benign or useful functionality");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-508","Non-Replicating Malicious Code","Non-replicating malicious code only resides on the target system or software that is attacked; it does not attempt to spread to other systems.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-509","Replicating Malicious Code (Virus or Worm)","Replicating malicious code");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-51","Path Equivalence: /multiple//internal/slash","A software system that accepts path input in the form of multiple internal slash (/multiple//internal/slash/) without appropriate validation can lead to ambiguous path resolution and allow an attacker to traverse the file system to unintended locations or access arbitrary files.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-510","Trapdoor","A trapdoor is a hidden piece of code that responds to a special input");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-511","Logic/Time Bomb","The software contains code that is designed to disrupt the legitimate operation of the software (or its environment) when a certain time passes");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-512","Spyware","The software collects personally identifiable information about a human user or the users activities");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-514","Covert Channel","A covert channel is a path that can be used to transfer information in a way not intended by the systems designers.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-515","Covert Storage Channel","A covert storage channel transfers information through the setting of bits by one program and the reading of those bits by another. What distinguishes this case from that of ordinary operation is that the bits are used to convey encoded information.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-52","Path Equivalence: /multiple/trailing/slash//","A software system that accepts path input in the form of multiple trailing slash (/multiple/trailing/slash//) without appropriate validation can lead to ambiguous path resolution and allow an attacker to traverse the file system to unintended locations or access arbitrary files.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-520",".NET Misconfiguration: Use of Impersonation","Allowing a .NET application to run at potentially escalated levels of access to the underlying operating and file systems can be dangerous and result in various forms of attacks.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-521","Weak Password Requirements","The product does not require that users should have strong passwords");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-522","Insufficiently Protected Credentials","This weakness occurs when the application transmits or stores authentication credentials and uses an insecure method that is susceptible to unauthorized interception and/or retrieval.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-523","Unprotected Transport of Credentials","Login pages not using adequate measures to protect the user name and password while they are in transit from the client to the server.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-524","Information Exposure Through Caching","The application uses a cache to maintain a pool of objects");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-525","Information Exposure Through Browser Caching","For each web page");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-526","Information Exposure Through Environmental Variables","Environmental variables may contain sensitive information about a remote server.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-527","Exposure of CVS Repository to an Unauthorized Control Sphere","The product stores a CVS repository in a directory or other container that is accessible to actors outside of the intended control sphere.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-528","Exposure of Core Dump File to an Unauthorized Control Sphere","The product generates a core dump file in a directory that is accessible to actors outside of the intended control sphere.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-529","Exposure of Access Control List Files to an Unauthorized Control Sphere","The product stores access control list files in a directory or other container that is accessible to actors outside of the intended control sphere.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-53","Path Equivalence: multipleinternalbackslash","A software system that accepts path input in the form of multiple internal backslash (multipletrailingslash) without appropriate validation can lead to ambiguous path resolution and allow an attacker to traverse the file system to unintended locations or access arbitrary files.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-530","Exposure of Backup File to an Unauthorized Control Sphere","A backup file is stored in a directory that is accessible to actors outside of the intended control sphere.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-531","Information Exposure Through Test Code","Accessible test applications can pose a variety of security risks. Since developers or administrators rarely consider that someone besides themselves would even know about the existence of these applications");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-532","Information Exposure Through Log Files","Information written to log files can be of a sensitive nature and give valuable guidance to an attacker or expose sensitive user information.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-533","Information Exposure Through Server Log Files","A server.log file was found. This can give information on whatever application left the file. Usually this can give full path names and system information");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-534","Information Exposure Through Debug Log Files","The application does not sufficiently restrict access to a log file that is used for debugging.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-535","Information Exposure Through Shell Error Message","A command shell error message indicates that there exists an unhandled exception in the web application code. In many cases");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-536","Information Exposure Through Servlet Runtime Error Message","A servlet error message indicates that there exists an unhandled exception in your web application code and may provide useful information to an attacker.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-537","Information Exposure Through Java Runtime Error Message","In many cases");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-538","File and Directory Information Exposure","The product stores sensitive information in files or directories that are accessible to actors outside of the intended control sphere.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-539","Information Exposure Through Persistent Cookies","Persistent cookies are cookies that are stored on the browsers hard drive. This can cause security and privacy issues depending on the information stored in the cookie and how it is accessed.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-54","Path Equivalence: filedir (Trailing Backslash)","A software system that accepts path input in the form of trailing backslash (filedir) without appropriate validation can lead to ambiguous path resolution and allow an attacker to traverse the file system to unintended locations or access arbitrary files.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-540","Information Exposure Through Source Code","Source code on a web server often contains sensitive information and should generally not be accessible to users.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-541","Information Exposure Through Include Source Code","If an include file source is accessible");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-542","Information Exposure Through Cleanup Log Files","The application does not properly protect or delete a log file related to cleanup.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-543","Use of Singleton Pattern Without Synchronization in a Multithreaded Context","The software uses the singleton pattern when creating a resource within a multithreaded environment.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-544","Missing Standardized Error Handling Mechanism","The software does not use a standardized method for handling errors throughout the code");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-546","Suspicious Comment","The code contains comments that suggest the presence of bugs");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-547","Use of Hard-coded","Draft");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-548","Information Exposure Through Directory Listing","A directory listing is inappropriately exposed");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-549","Missing Password Field Masking","The software does not mask passwords during entry");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-55","Path Equivalence: /./ (Single Dot Directory)","A software system that accepts path input in the form of single dot directory exploit (/./) without appropriate validation can lead to ambiguous path resolution and allow an attacker to traverse the file system to unintended locations or access arbitrary files.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-550","Information Exposure Through Server Error Message","Certain conditions");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-551","Incorrect Behavior Order: Authorization Before Parsing and Canonicalization","If a web server does not fully parse requested URLs before it examines them for authorization");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-552","Files or Directories Accessible to External Parties","Files or directories are accessible in the environment that should not be.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-553","Command Shell in Externally Accessible Directory","A possible shell file exists in /cgi-bin/ or other accessible directories. This is extremely dangerous and can be used by an attacker to execute commands on the web server.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-554","ASP.NET Misconfiguration: Not Using Input Validation Framework","The ASP.NET application does not use an input validation framework.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-555","J2EE Misconfiguration: Plaintext Password in Configuration File","The J2EE application stores a plaintext password in a configuration file.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-556","ASP.NET Misconfiguration: Use of Identity Impersonation","Configuring an ASP.NET application to run with impersonated credentials may give the application unnecessary privileges.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-558","Use of getlogin() in Multithreaded Application","The application uses the getlogin() function in a multithreaded context");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-56","Path Equivalence: filedir* (Wildcard)","A software system that accepts path input in the form of asterisk wildcard (filedir*) without appropriate validation can lead to ambiguous path resolution and allow an attacker to traverse the file system to unintended locations or access arbitrary files.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-560","Use of umask() with chmod-style Argument","The product calls umask() with an incorrect argument that is specified as if it is an argument to chmod().");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-561","Dead Code","The software contains dead code");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-562","Return of Stack Variable Address","A function returns the address of a stack variable");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-563","Assignment to Variable without Use","The variables value is assigned but never used");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-564","SQL Injection: Hibernate","Using Hibernate to execute a dynamic SQL statement built with user-controlled input can allow an attacker to modify the statements meaning or to execute arbitrary SQL commands.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-565","Reliance on Cookies without Validation and Integrity Checking","The application relies on the existence or values of cookies when performing security-critical operations");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-566","Authorization Bypass Through User-Controlled SQL Primary Key","The software uses a database table that includes records that should not be accessible to an actor");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-567","Unsynchronized Access to Shared Data in a Multithreaded Context","The product does not properly synchronize shared data");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-568","finalize() Method Without super.finalize()","The software contains a finalize() method that does not call super.finalize().");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-57","Path Equivalence: fakedir/../realdir/filename","The software contains protection mechanisms to restrict access to realdir/filename");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-570","Expression is Always False","The software contains an expression that will always evaluate to false.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-571","Expression is Always True","The software contains an expression that will always evaluate to true.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-572","Call to Thread run() instead of start()","The program calls a threads run() method instead of calling start()");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-573","Improper Following of Specification by Caller","The software does not follow or incorrectly follows the specifications as required by the implementation language");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-574","EJB Bad Practices: Use of Synchronization Primitives","The program violates the Enterprise JavaBeans (EJB) specification by using thread synchronization primitives.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-575","EJB Bad Practices: Use of AWT Swing","The program violates the Enterprise JavaBeans (EJB) specification by using AWT/Swing.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-576","EJB Bad Practices: Use of Java I/O","The program violates the Enterprise JavaBeans (EJB) specification by using the java.io package.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-577","EJB Bad Practices: Use of Sockets","The program violates the Enterprise JavaBeans (EJB) specification by using sockets.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-578","EJB Bad Practices: Use of Class Loader","The program violates the Enterprise JavaBeans (EJB) specification by using the class loader.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-579","J2EE Bad Practices: Non-serializable Object Stored in Session","The application stores a non-serializable object as an HttpSession attribute");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-58","Path Equivalence: Windows 8.3 Filename","The software contains a protection mechanism that restricts access to a long filename on a Windows operating system");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-580","clone() Method Without super.clone()","The software contains a clone() method that does not call super.clone() to obtain the new object.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-581","Object Model Violation: Just One of Equals and Hashcode Defined","The software does not maintain equal hashcodes for equal objects.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-582","Array Declared Public","Variant");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-583","finalize() Method Declared Public","The program violates secure coding principles for mobile code by declaring a finalize() method public.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-584","Return Inside Finally Block","The code has a return statement inside a finally block");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-585","Empty Synchronized Block","The software contains an empty synchronized block.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-586","Explicit Call to Finalize()","The software makes an explicit call to the finalize() method from outside the finalizer.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-587","Assignment of a Fixed Address to a Pointer","The software sets a pointer to a specific address other than NULL or 0.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-588","Attempt to Access Child of a Non-structure Pointer","Casting a non-structure type to a structure type and accessing a field can lead to memory access errors or data corruption.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-589","Call to Non-ubiquitous API","The software uses an API function that does not exist on all versions of the target platform. This could cause portability problems or inconsistencies that allow denial of service or other consequences.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-59","Improper Link Resolution Before File Access (Link Following)","The software attempts to access a file based on the filename");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-590","Free of Memory not on the Heap","The application calls free() on a pointer to memory that was not allocated using associated heap allocation functions such as malloc()");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-591","Sensitive Data Storage in Improperly Locked Memory","The application stores sensitive data in memory that is not locked");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-593","Authentication Bypass: OpenSSL CTX Object Modified after SSL Objects are Created","The software modifies the SSL context after connection creation has begun.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-594","J2EE Framework: Saving Unserializable Objects to Disk","When the J2EE container attempts to write unserializable objects to disk there is no guarantee that the process will complete successfully.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-595","Comparison of Object References Instead of Object Contents","The program compares object references instead of the contents of the objects themselves");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-596","Incorrect Semantic Object Comparison","The software does not correctly compare two objects based on their conceptual content.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-597","Use of Wrong Operator in String Comparison","The product uses the wrong operator when comparing a string");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-598","Information Exposure Through Query Strings in GET Request","The web application uses the GET method to process requests that contain sensitive information");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-599","Missing Validation of OpenSSL Certificate","The software uses OpenSSL and trusts or uses a certificate without using the SSL_get_verify_result() function to ensure that the certificate satisfies all necessary security requirements.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-6","J2EE Misconfiguration: Insufficient Session-ID Length","The J2EE application is configured to use an insufficient session ID length.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-600","Uncaught Exception in Servlet ","The Servlet does not catch all exceptions");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-601","URL Redirection to Untrusted Site (Open Redirect)","A web application accepts a user-controlled input that specifies a link to an external site");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-602","Client-Side Enforcement of Server-Side Security","The software is composed of a server that relies on the client to implement a mechanism that is intended to protect the server.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-603","Use of Client-Side Authentication","A client/server product performs authentication within client code but not in server code");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-605","Multiple Binds to the Same Port","When multiple sockets are allowed to bind to the same port");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-606","Unchecked Input for Loop Condition","The product does not properly check inputs that are used for loop conditions");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-607","Public Static Final Field References Mutable Object","A public or protected static final field references a mutable object");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-608","Struts: Non-private Field in ActionForm Class","An ActionForm class contains a field that has not been declared private");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-609","Double-Checked Locking","The program uses double-checked locking to access a resource without the overhead of explicit synchronization");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-61","UNIX Symbolic Link (Symlink) Following","The software");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-610","Externally Controlled Reference to a Resource in Another Sphere","The product uses an externally controlled name or reference that resolves to a resource that is outside of the intended control sphere.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-611","Improper Restriction of XML External Entity Reference (XXE)","The software processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-612","Information Exposure Through Indexing of Private Data","The product performs an indexing routine against private documents");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-613","Insufficient Session Expiration","According to WASC");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-614","Sensitive Cookie in HTTPS Session Without Secure Attribute","The Secure attribute for sensitive cookies in HTTPS sessions is not set");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-615","Information Exposure Through Comments","While adding general comments is very useful");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-616","Incomplete Identification of Uploaded File Variables (PHP)","The PHP application uses an old method for processing uploaded files by referencing the four global variables that are set for each file (e.g. $varname");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-617","Reachable Assertion","The product contains an assert() or similar statement that can be triggered by an attacker");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-618","Exposed Unsafe ActiveX Method","An ActiveX control is intended for use in a web browser");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-619","Dangling Database Cursor (Cursor Injection)","If a database cursor is not closed properly");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-62","UNIX Hard Link","The software");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-620","Unverified Password Change","When setting a new password for a user");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-621","Variable Extraction Error","The product uses external input to determine the names of variables into which information is extracted");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-622","Improper Validation of Function Hook Arguments","A product adds hooks to user-accessible API functions");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-623","Unsafe ActiveX Control Marked Safe For Scripting","An ActiveX control is intended for restricted use");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-624","Executable Regular Expression Error","The product uses a regular expression that either (1) contains an executable component with user-controlled inputs");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-625","Permissive Regular Expression","The product uses a regular expression that does not sufficiently restrict the set of allowed values.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-626","Null Byte Interaction Error (Poison Null Byte)","The product does not properly handle null bytes or NUL characters when passing data between different representations or components.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-627","Dynamic Variable Evaluation","In a language where the user can influence the name of a variable at runtime");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-628","Function Call with Incorrectly Specified Arguments","The product calls a function");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-636","Not Failing Securely (Failing Open)","When the product encounters an error condition or failure");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-637","Unnecessary Complexity in Protection Mechanism (Not Using Economy of Mechanism)","The software uses a more complex mechanism than necessary");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-638","Not Using Complete Mediation","The software does not perform access checks on a resource every time the resource is accessed by an entity");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-639","Authorization Bypass Through User-Controlled Key","The systems authorization functionality does not prevent one user from gaining access to another users data or record by modifying the key value identifying the data.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-64","Windows Shortcut Following (.LNK)","The software");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-640","Weak Password Recovery Mechanism for Forgotten Password","The software contains a mechanism for users to recover or change their passwords without knowing the original password");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-641","Improper Restriction of Names for Files and Other Resources","The application constructs the name of a file or other resource using input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-642","External Control of Critical State Data","The software stores security-critical state information about its users");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-643","Improper Neutralization of Data within XPath Expressions (XPath Injection)","The software uses external input to dynamically construct an XPath expression used to retrieve data from an XML database");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-644","Improper Neutralization of HTTP Headers for Scripting Syntax","The application does not neutralize or incorrectly neutralizes web scripting syntax in HTTP headers that can be used by web browser components that can process raw headers");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-645","Overly Restrictive Account Lockout Mechanism","The software contains an account lockout protection mechanism");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-646","Reliance on File Name or Extension of Externally-Supplied File","The software allows a file to be uploaded");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-647","Use of Non-Canonical URL Paths for Authorization Decisions","The software defines policy namespaces and makes authorization decisions based on the assumption that a URL is canonical. This can allow a non-canonical URL to bypass the authorization.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-648","Incorrect Use of Privileged APIs","The application does not conform to the API requirements for a function call that requires extra privileges. This could allow attackers to gain privileges by causing the function to be called incorrectly.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-649","Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity Checking","The software uses obfuscation or encryption of inputs that should not be mutable by an external actor");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-65","Windows Hard Link","The software");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-650","Trusting HTTP Permission Methods on the Server Side","The server contains a protection mechanism that assumes that any URI that is accessed using HTTP GET will not cause a state change to the associated resource. This might allow attackers to bypass intended access restrictions and conduct resource modification and deletion attacks");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-651","Information Exposure Through WSDL File","The Web services architecture may require exposing a Web Service Definition Language (WSDL) file that contains information on the publicly accessible services and how callers of these services should interact with them (e.g. what parameters they expect and what types they return).");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-652","Improper Neutralization of Data within XQuery Expressions (XQuery Injection)","The software uses external input to dynamically construct an XQuery expression used to retrieve data from an XML database");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-653","Insufficient Compartmentalization","The product does not sufficiently compartmentalize functionality or processes that require different privilege levels");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-654","Reliance on a Single Factor in a Security Decision","A protection mechanism relies exclusively");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-655","Insufficient Psychological Acceptability","The software has a protection mechanism that is too difficult or inconvenient to use");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-656","Reliance on Security Through Obscurity","The software uses a protection mechanism whose strength depends heavily on its obscurity");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-657","Violation of Secure Design Principles","The product violates well-established principles for secure design.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-66","Improper Handling of File Names that Identify Virtual Resources","The product does not handle or incorrectly handles a file name that identifies a virtual resource that is not directly specified within the directory that is associated with the file name");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-662","Improper Synchronization","The software attempts to use a shared resource in an exclusive manner");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-663","Use of a Non-reentrant Function in a Concurrent Context","The software calls a non-reentrant function in a concurrent context in which a competing code sequence (e.g. thread or signal handler) may have an opportunity to call the same function or otherwise influence its state.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-664","Improper Control of a Resource Through its Lifetime","The software does not maintain or incorrectly maintains control over a resource throughout its lifetime of creation");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-665","Improper Initialization","The software does not initialize or incorrectly initializes a resource");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-666","Operation on Resource in Wrong Phase of Lifetime","The software performs an operation on a resource at the wrong phase of the resources lifecycle");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-667","Improper Locking","The software does not properly acquire a lock on a resource");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-668","Exposure of Resource to Wrong Sphere","The product exposes a resource to the wrong control sphere");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-669","Incorrect Resource Transfer Between Spheres","The product does not properly transfer a resource/behavior to another sphere");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-67","Improper Handling of Windows Device Names","The software constructs pathnames from user input");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-670","Always-Incorrect Control Flow Implementation","The code contains a control flow path that does not reflect the algorithm that the path is intended to implement");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-671","Lack of Administrator Control over Security","The product uses security features in a way that prevents the products administrator from tailoring security settings to reflect the environment in which the product is being used. This introduces resultant weaknesses or prevents it from operating at a level of security that is desired by the administrator.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-672","Operation on a Resource after Expiration or Release","The software uses");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-673","External Influence of Sphere Definition","The product does not prevent the definition of control spheres from external actors.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-674","Uncontrolled Recursion","The product does not properly control the amount of recursion that takes place");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-675","Duplicate Operations on Resource","The product performs the same operation on a resource two or more times");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-676","Use of Potentially Dangerous Function","The program invokes a potentially dangerous function that could introduce a vulnerability if it is used incorrectly");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-680","Integer Overflow to Buffer Overflow","The product performs a calculation to determine how much memory to allocate");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-681","Incorrect Conversion between Numeric Types","When converting from one data type to another");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-682","Incorrect Calculation","The software performs a calculation that generates incorrect or unintended results that are later used in security-critical decisions or resource management.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-683","Function Call With Incorrect Order of Arguments","The software calls a function");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-684","Incorrect Provision of Specified Functionality","The code does not function according to its published specifications");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-685","Function Call With Incorrect Number of Arguments","The software calls a function");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-686","Function Call With Incorrect Argument Type","The software calls a function");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-687","Function Call With Incorrectly Specified Argument Value","The software calls a function");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-688","Function Call With Incorrect Variable or Reference as Argument","The software calls a function");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-689","Permission Race Condition During Resource Copy","The product");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-69","Improper Handling of Windows ::DATA Alternate Data Stream","The software does not properly prevent access to");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-690","Unchecked Return Value to NULL Pointer Dereference","The product does not check for an error after calling a function that can return with a NULL pointer if the function fails");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-691","Insufficient Control Flow Management","The code does not sufficiently manage its control flow during execution");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-692","Incomplete Blacklist to Cross-Site Scripting","The product uses a blacklist-based protection mechanism to defend against XSS attacks");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-693","Protection Mechanism Failure","The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the product.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-694","Use of Multiple Resources with Duplicate Identifier","The software uses multiple resources that can have the same identifier");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-695","Use of Low-Level Functionality","The software uses low-level functionality that is explicitly prohibited by the framework or specification under which the software is supposed to operate.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-696","Incorrect Behavior Order","The software performs multiple related behaviors");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-697","Insufficient Comparison","The software compares two entities in a security-relevant context");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-698","Execution After Redirect (EAR)","The web application sends a redirect to another location");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-7","J2EE Misconfiguration: Missing Custom Error Page","The default error page of a web application should not display sensitive information about the software system.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-703","Improper Check or Handling of Exceptional Conditions","The software does not properly anticipate or handle exceptional conditions that rarely occur during normal operation of the software.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-704","Incorrect Type Conversion or Cast","The software does not correctly convert an object");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-705","Incorrect Control Flow Scoping","The software does not properly return control flow to the proper location after it has completed a task or detected an unusual condition.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-706","Use of Incorrectly-Resolved Name or Reference","The software uses a name or reference to access a resource");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-707","Improper Enforcement of Message or Data Structure","The software does not enforce or incorrectly enforces that structured messages or data are well-formed before being read from an upstream component or sent to a downstream component.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-708","Incorrect Ownership Assignment","The software assigns an owner to a resource");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-710","Improper Adherence to Coding Standards","The software does not follow certain coding rules for development");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-72","Improper Handling of Apple HFS+ Alternate Data Stream Path","The software does not properly handle special paths that may identify the data or resource fork of a file on the HFS+ file system.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-73","External Control of File Name or Path","The software allows user input to control or influence paths or file names that are used in filesystem operations.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-732","Incorrect Permission Assignment for Critical Resource","The software specifies permissions for a security-critical resource in a way that allows that resource to be read or modified by unintended actors.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-733","Compiler Optimization Removal or Modification of Security-critical Code","The developer builds a security-critical protection mechanism into the software but the compiler optimizes the program such that the mechanism is removed or modified.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-74","Improper Neutralization of Special Elements in Output Used by a Downstream Component (Injection)","The software constructs all or part of a command");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-749","Exposed Dangerous Method or Function","The software provides an Applications Programming Interface (API) or similar interface for interaction with external actors");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-75","Failure to Sanitize Special Elements into a Different Plane (Special Element Injection)","The software does not adequately filter user-controlled input for special elements with control implications.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-754","Improper Check for Unusual or Exceptional Conditions","The software does not check or improperly checks for unusual or exceptional conditions that are not expected to occur frequently during day to day operation of the software.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-755","Improper Handling of Exceptional Conditions","The software does not handle or incorrectly handles an exceptional condition.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-756","Missing Custom Error Page","The software does not return custom error pages to the user");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-757","Selection of Less-Secure Algorithm During Negotiation (Algorithm Downgrade)","A protocol or its implementation supports interaction between multiple actors and allows those actors to negotiate which algorithm should be used as a protection mechanism such as encryption or authentication");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-758","Reliance on Undefined","Class");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-759","Use of a One-Way Hash without a Salt","The software uses a one-way cryptographic hash against an input that should not be reversible");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-76","Improper Neutralization of Equivalent Special Elements","The software properly neutralizes certain special elements");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-760","Use of a One-Way Hash with a Predictable Salt","The software uses a one-way cryptographic hash against an input that should not be reversible");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-761","Free of Pointer not at Start of Buffer","The application calls free() on a pointer to a memory resource that was allocated on the heap");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-762","Mismatched Memory Management Routines","The application attempts to return a memory resource to the system");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-763","Release of Invalid Pointer or Reference","The application attempts to return a memory resource to the system");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-764","Multiple Locks of a Critical Resource","The software locks a critical resource more times than intended");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-765","Multiple Unlocks of a Critical Resource","The software unlocks a critical resource more times than intended");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-766","Critical Variable Declared Public","The software declares a critical variable or field to be public when intended security policy requires it to be private.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-767","Access to Critical Private Variable via Public Method","The software defines a public method that reads or modifies a private variable.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-768","Incorrect Short Circuit Evaluation","The software contains a conditional statement with multiple logical expressions in which one of the non-leading expressions may produce side effects. This may lead to an unexpected state in the program after the execution of the conditional");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-769","Uncontrolled File Descriptor Consumption","The software does not properly limit the number of open file descriptors that it uses.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-77","Improper Neutralization of Special Elements used in a Command (Command Injection)","The software constructs all or part of a command using externally-influenced input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-770","Allocation of Resources Without Limits or Throttling","The software allocates a reusable resource or group of resources on behalf of an actor without imposing any restrictions on how many resources can be allocated");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-771","Missing Reference to Active Allocated Resource","The software does not properly maintain a reference to a resource that has been allocated");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-772","Missing Release of Resource after Effective Lifetime","The software does not release a resource after its effective lifetime has ended");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-773","Missing Reference to Active File Descriptor or Handle","The software does not properly maintain references to a file descriptor or handle");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-774","Allocation of File Descriptors or Handles Without Limits or Throttling","The software allocates file descriptors or handles on behalf of an actor without imposing any restrictions on how many descriptors can be allocated");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-775","Missing Release of File Descriptor or Handle after Effective Lifetime","The software does not release a file descriptor or handle after its effective lifetime has ended");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-776","Improper Restriction of Recursive Entity References in DTDs (XML Entity Expansion)","The software uses XML documents and allows their structure to be defined with a Document Type Definition (DTD)");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-777","Regular Expression without Anchors","The software uses a regular expression to perform neutralization");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-778","Insufficient Logging","When a security-critical event occurs");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-779","Logging of Excessive Data","The software logs too much information");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-78","Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)","The software constructs all or part of an OS command using externally-influenced input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-780","Use of RSA Algorithm without OAEP","The software uses the RSA algorithm but does not incorporate Optimal Asymmetric Encryption Padding (OAEP)");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-781","Improper Address Validation in IOCTL with METHOD_NEITHER I/O Control Code","The software defines an IOCTL that uses METHOD_NEITHER for I/O");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-782","Exposed IOCTL with Insufficient Access Control","The software implements an IOCTL with functionality that should be restricted");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-783","Operator Precedence Logic Error","The program uses an expression in which operator precedence causes incorrect logic to be used.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-784","Reliance on Cookies without Validation and Integrity Checking in a Security Decision","The application uses a protection mechanism that relies on the existence or values of a cookie");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-785","Use of Path Manipulation Function without Maximum-sized Buffer","The software invokes a function for normalizing paths or file names");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-786","Access of Memory Location Before Start of Buffer","The software reads or writes to a buffer using an index or pointer that references a memory location prior to the beginning of the buffer.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-787","Out-of-bounds Write","The software writes data past the end");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-788","Access of Memory Location After End of Buffer","The software reads or writes to a buffer using an index or pointer that references a memory location after the end of the buffer.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-789","Uncontrolled Memory Allocation","The product allocates memory based on an untrusted size value");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-79","Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)","The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-790","Improper Filtering of Special Elements","The software receives data from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-791","Incomplete Filtering of Special Elements","The software receives data from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-792","Incomplete Filtering of One or More Instances of Special Elements","The software receives data from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-793","Only Filtering One Instance of a Special Element","The software receives data from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-794","Incomplete Filtering of Multiple Instances of Special Elements","The software receives data from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-795","Only Filtering Special Elements at a Specified Location","The software receives data from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-796","Only Filtering Special Elements Relative to a Marker","The software receives data from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-797","Only Filtering Special Elements at an Absolute Position","The software receives data from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-798","Use of Hard-coded Credentials","The software contains hard-coded credentials");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-799","Improper Control of Interaction Frequency","The software does not properly limit the number or frequency of interactions that it has with an actor");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-8","J2EE Misconfiguration: Entity Bean Declared Remote","When an application exposes a remote interface for an entity bean");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-80","Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)","The software receives input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-804","Guessable CAPTCHA","The software uses a CAPTCHA challenge");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-805","Buffer Access with Incorrect Length Value","The software uses a sequential operation to read or write a buffer");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-806","Buffer Access Using Size of Source Buffer","The software uses the size of a source buffer when reading from or writing to a destination buffer");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-807","Reliance on Untrusted Inputs in a Security Decision","The application uses a protection mechanism that relies on the existence or values of an input");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-81","Improper Neutralization of Script in an Error Message Web Page","The software receives input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-82","Improper Neutralization of Script in Attributes of IMG Tags in a Web Page","The web application does not neutralize or incorrectly neutralizes scripting elements within attributes of HTML IMG tags");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-820","Missing Synchronization","The software utilizes a shared resource in a concurrent manner but does not attempt to synchronize access to the resource.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-821","Incorrect Synchronization","The software utilizes a shared resource in a concurrent manner but it does not correctly synchronize access to the resource.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-822","Untrusted Pointer Dereference","The program obtains a value from an untrusted source");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-823","Use of Out-of-range Pointer Offset","The program performs pointer arithmetic on a valid pointer");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-824","Access of Uninitialized Pointer","The program accesses or uses a pointer that has not been initialized.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-825","Expired Pointer Dereference","The program dereferences a pointer that contains a location for memory that was previously valid");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-826","Premature Release of Resource During Expected Lifetime","The program releases a resource that is still intended to be used by the program itself or another actor.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-827","Improper Control of Document Type Definition","The software does not restrict a reference to a Document Type Definition (DTD) to the intended control sphere. This might allow attackers to reference arbitrary DTDs");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-828","Signal Handler with Functionality that is not Asynchronous-Safe","The software defines a signal handler that contains code sequences that are not asynchronous-safe");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-829","Inclusion of Functionality from Untrusted Control Sphere","The software imports");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-83","Improper Neutralization of Script in Attributes in a Web Page","The software does not neutralize or incorrectly neutralizes javascript: or other URIs from dangerous attributes within tags");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-830","Inclusion of Web Functionality from an Untrusted Source","The software includes web functionality (such as a web widget) from another domain");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-831","Signal Handler Function Associated with Multiple Signals","The software defines a function that is used as a handler for more than one signal.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-832","Unlock of a Resource that is not Locked","The software attempts to unlock a resource that is not locked.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-833","Deadlock","The software contains multiple threads or executable segments that are waiting for each other to release a necessary lock");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-834","Excessive Iteration","The software performs an iteration or loop without sufficiently limiting the number of times that the loop is executed.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-835","Loop with Unreachable Exit Condition (Infinite Loop)","The program contains an iteration or loop with an exit condition that cannot be reached");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-836","Use of Password Hash Instead of Password for Authentication","The software records password hashes in a data store");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-837","Improper Enforcement of a Single","Incomplete");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-838","Inappropriate Encoding for Output Context","The software uses or specifies an encoding when generating output to a downstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-839","Numeric Range Comparison Without Minimum Check","The program checks a value to ensure that it does not exceed a maximum");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-84","Improper Neutralization of Encoded URI Schemes in a Web Page","The web application improperly neutralizes user-controlled input for executable script disguised with URI encodings.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-841","Improper Enforcement of Behavioral Workflow","The software supports a session in which more than one behavior must be performed by an actor");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-842","Placement of User into Incorrect Group","The software or the administrator places a user into an incorrect group.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-843","Access of Resource Using Incompatible Type (Type Confusion)","The program allocates or initializes a resource such as a pointer");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-85","Doubled Character XSS Manipulations","The web application does not filter user-controlled input for executable script disguised using doubling of the involved characters.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-86","Improper Neutralization of Invalid Characters in Identifiers in Web Pages","The software does not neutralize or incorrectly neutralizes invalid characters or byte sequences in the middle of tag names");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-862","Missing Authorization","The software does not perform an authorization check when an actor attempts to access a resource or perform an action.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-863","Incorrect Authorization","The software performs an authorization check when an actor attempts to access a resource or perform an action");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-87","Improper Neutralization of Alternate XSS Syntax","The software does not neutralize or incorrectly neutralizes user-controlled input for alternate script syntax.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-88","Argument Injection or Modification","The software does not sufficiently delimit the arguments being passed to a component in another control sphere");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-89","Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)","The software constructs all or part of an SQL command using externally-influenced input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-9","J2EE Misconfiguration: Weak Access Permissions for EJB Methods","If elevated access rights are assigned to EJB methods");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-90","Improper Neutralization of Special Elements used in an LDAP Query (LDAP Injection)","The software constructs all or part of an LDAP query using externally-influenced input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-908","Use of Uninitialized Resource","The software uses a resource that has not been properly initialized.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-909","Missing Initialization of Resource","The software does not initialize a critical resource.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-91","XML Injection (aka Blind XPath Injection)","The software does not properly neutralize special elements that are used in XML");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-910","Use of Expired File Descriptor","The software uses or accesses a file descriptor after it has been closed.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-911","Improper Update of Reference Count","The software uses a reference count to manage a resource");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-912","Hidden Functionality","The software contains functionality that is not documented");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-913","Improper Control of Dynamically-Managed Code Resources","The software does not properly restrict reading from or writing to dynamically-managed code resources such as variables");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-914","Improper Control of Dynamically-Identified Variables","The software does not properly restrict reading from or writing to dynamically-identified variables.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-915","Improperly Controlled Modification of Dynamically-Determined Object Attributes","The software receives input from an upstream component that specifies multiple attributes");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-916","Use of Password Hash With Insufficient Computational Effort","The software generates a hash for a password");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-917","Improper Neutralization of Special Elements used in an Expression Language Statement (Expression Language Injection)","The software constructs all or part of an expression language (EL) statement in a Java Server Page (JSP) using externally-influenced input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-918","Server-Side Request Forgery (SSRF)","The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-920","Improper Restriction of Power Consumption","The software operates in an environment in which power is a limited resource that cannot be automatically replenished");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-921","Storage of Sensitive Data in a Mechanism without Access Control","The software stores sensitive information in a file system or device that does not have built-in access control.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-922","Insecure Storage of Sensitive Information","The software stores sensitive information without properly limiting read or write access by unauthorized actors.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-923","Improper Restriction of Communication Channel to Intended Endpoints","The software establishes a communication channel to (or from) an endpoint for privileged or protected operations");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-924","Improper Enforcement of Message Integrity During Transmission in a Communication Channel","The software establishes a communication channel with an endpoint and receives a message from that endpoint");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-925","Improper Verification of Intent by Broadcast Receiver","The Android application uses a Broadcast Receiver that receives an Intent but does not properly verify that the Intent came from an authorized source.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-926","Improper Export of Android Application Components","The Android application exports a component for use by other applications");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-927","Use of Implicit Intent for Sensitive Communication","The Android application uses an implicit intent for transmitting sensitive data to other applications.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-93","Improper Neutralization of CRLF Sequences (CRLF Injection)","The software uses CRLF (carriage return line feeds) as a special element");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-939","Improper Authorization in Handler for Custom URL Scheme","The software uses a handler for a custom URL scheme");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-94","Improper Control of Generation of Code (Code Injection)","The software constructs all or part of a code segment using externally-influenced input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-940","Improper Verification of Source of a Communication Channel","The software establishes a communication channel to handle an incoming request that has been initiated by an actor");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-941","Incorrectly Specified Destination in a Communication Channel","The software creates a communication channel to initiate an outgoing request to an actor");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-942","Overly Permissive Cross-domain Whitelist","The software uses a cross-domain policy file that includes domains that should not be trusted.");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-943","Improper Neutralization of Special Elements in Data Query Logic","The application generates a query intended to access or manipulate data in a data store such as a database");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-95","Improper Neutralization of Directives in Dynamically Evaluated Code (Eval Injection)","The software receives input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-96","Improper Neutralization of Directives in Statically Saved Code (Static Code Injection)","The software receives input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-97","Improper Neutralization of Server-Side Includes (SSI) Within a Web Page","The software generates a web page");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-98","Improper Control of Filename for Include/Require Statement in PHP Program (PHP Remote File Inclusion)","The PHP application receives input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-99","Improper Control of Resource Identifiers (Resource Injection)","The software receives input from an upstream component");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-NVD-Other","","");
INSERT INTO `vulinoss`.`cwe` (cwe,name,description) VALUES ("CWE-NVD-noinfo","","");
-- Populating programming languages --
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (1,'ABAP');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (2,'ActionScript');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (3,'Ada');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (4,'ADSO/IDSM');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (5,'AMPLE');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (6,'Ant');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (7,'ANTLR Grammar');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (8,'Apex Trigger');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (9,'Arduino Sketch');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (10,'ASP');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (11,'ASP.NET');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (12,'AspectJ');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (13,'Assembly');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (14,'AutoHotkey');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (15,'awk');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (16,'Blade');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (17,'Bourne Again Shell');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (18,'Bourne Shell');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (19,'BrightScript');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (20,'builder');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (21,'C');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (22,'C Shell');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (23,'C#');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (24,'C++');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (25,'C/C++ Header');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (26,'CCS');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (27,'Chapel');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (28,'Clean');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (29,'Clojure');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (30,'ClojureC');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (31,'ClojureScript');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (32,'CMake');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (33,'COBOL');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (34,'CoffeeScript');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (35,'ColdFusion');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (36,'ColdFusion CFScript');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (37,'Coq');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (38,'Crystal');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (39,'CSON');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (40,'CSS');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (41,'Cucumber');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (42,'CUDA');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (43,'Cython');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (44,'D');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (45,'DAL');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (46,'Dart');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (47,'diff');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (48,'DITA');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (49,'DOORS Extension Language');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (50,'DOS Batch');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (51,'Drools');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (52,'DTD');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (53,'dtrace');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (54,'ECPP');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (55,'EEx');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (56,'Elixir');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (57,'Elm');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (58,'ERB');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (59,'Erlang');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (60,'Expect');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (61,'F#');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (62,'F# Script');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (63,'Focus');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (64,'Forth');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (65,'Fortran 77');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (66,'Fortran 90');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (67,'Fortran 95');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (68,'Freemarker Template');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (69,'GDScript');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (70,'Glade');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (71,'GLSL');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (72,'Go');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (73,'Grails');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (74,'GraphQL');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (75,'Groovy');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (76,'Haml');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (77,'Handlebars');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (78,'Harbour');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (79,'Haskell');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (80,'Haxe');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (81,'HLSL');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (82,'HTML');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (83,'IDL');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (84,'Idris');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (85,'INI');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (86,'InstallShield');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (87,'Java');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (88,'JavaScript');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (89,'JavaServer Faces');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (90,'JCL');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (91,'JSON');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (92,'JSP');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (93,'JSX');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (94,'Julia');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (95,'Kermit');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (96,'Korn Shell');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (97,'Kotlin');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (98,'LESS');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (99,'lex');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (100,'LFE');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (101,'liquid');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (102,'Lisp');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (103,'Literate Idris');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (104,'LiveLink OScript');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (105,'Logtalk');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (106,'Lua');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (107,'m4');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (108,'make');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (109,'Mako');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (110,'Markdown');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (111,'Mathematica');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (112,'MATLAB');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (113,'Maven');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (114,'Modula3');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (115,'MSBuild script');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (116,'MUMPS');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (117,'Mustache');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (118,'MXML');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (119,'NAnt script');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (120,'NASTRAN DMAP');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (121,'Nemerle');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (122,'Nim');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (123,'Objective C');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (124,'Objective C++');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (125,'OCaml');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (126,'OpenCL');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (127,'Oracle Forms');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (128,'Oracle Reports');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (129,'Pascal');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (130,'Pascal/Puppet');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (131,'Patran Command Language');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (132,'Perl');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (133,'PHP');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (134,'PHP/Pascal');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (135,'Pig');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (136,'PL/I');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (137,'PO File');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (138,'PowerBuilder');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (139,'PowerShell');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (140,'Prolog');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (141,'Protocol Buffers');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (142,'Pug');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (143,'PureScript');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (144,'Python');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (145,'QML');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (146,'Qt');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (147,'Qt Linguist');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (148,'Qt Project');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (149,'R');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (150,'Racket');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (151,'RapydScript');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (152,'Razor');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (153,'Rexx');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (154,'RobotFramework');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (155,'Ruby');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (156,'Ruby HTML');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (157,'Rust');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (158,'SAS');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (159,'Sass');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (160,'Scala');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (161,'Scheme');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (162,'sed');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (163,'SKILL');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (164,'SKILL++');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (165,'Slice');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (166,'Slim');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (167,'Smalltalk');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (168,'Smarty');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (169,'Softbridge Basic');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (170,'Solidity');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (171,'Specman e');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (172,'SQL');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (173,'SQL Data');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (174,'SQL Stored Procedure');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (175,'Standard ML');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (176,'Stata');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (177,'Stylus');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (178,'Swift');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (179,'Tcl/Tk');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (180,'Teamcenter met');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (181,'Teamcenter mth');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (182,'TeX');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (183,'TITAN Project File Information');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (184,'Titanium Style Sheet');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (185,'TOML');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (186,'TTCN');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (187,'Twig');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (188,'TypeScript');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (189,'Unity-Prefab');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (191,'Vala');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (192,'Velocity Template Language');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (193,'Verilog-SystemVerilog');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (194,'VHDL');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (195,'vim script');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (196,'Visual Basic');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (197,'Visual Fox Pro');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (198,'Visualforce Component');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (199,'Visualforce Page');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (200,'Vuejs Component');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (201,'Windows Message File');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (202,'Windows Module Definition');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (203,'Windows Resource File');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (204,'WiX include');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (205,'WiX source');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (206,'WiX string localization');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (207,'XAML');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (208,'xBase');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (209,'xBase Header');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (210,'XHTML');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (211,'XMI');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (212,'XML');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (213,'XQuery');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (214,'XSD');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (215,'XSLT');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (216,'yacc');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (217,'YAML');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (218,'zsh');
INSERT INTO `vulinoss`.`programming_languages` (id,plname) VALUES (219,'Puppet');
-- Populate the Continuous Integration Providers table --
INSERT INTO `vulinoss`.`continuous_integration_providers` (id,ciname) VALUES (1,'Travis');
INSERT INTO `vulinoss`.`continuous_integration_providers` (id,ciname) VALUES (2,'AppVeyor');
INSERT INTO `vulinoss`.`continuous_integration_providers` (id,ciname) VALUES (3,'Magnum');
INSERT INTO `vulinoss`.`continuous_integration_providers` (id,ciname) VALUES (4,'Circle');
INSERT INTO `vulinoss`.`continuous_integration_providers` (id,ciname) VALUES (5,'Hound');
INSERT INTO `vulinoss`.`continuous_integration_providers` (id,ciname) VALUES (6,'Scrutinizer');
INSERT INTO `vulinoss`.`continuous_integration_providers` (id,ciname) VALUES (7,'Shippable');
INSERT INTO `vulinoss`.`continuous_integration_providers` (id,ciname) VALUES (8,'Solano');
INSERT INTO `vulinoss`.`continuous_integration_providers` (id,ciname) VALUES (9,'Wercker');
-- Populate the Software Categories table --
INSERT INTO `vulinoss`.`software_categories` (id,scname,description) VALUES (1,'Operating systems','Low-level software that supports a computer basic functions, such as scheduling tasks and controlling peripherals');
INSERT INTO `vulinoss`.`software_categories` (id,scname,description) VALUES (2,'End-user applications','Computer software that provides specific functions for an individual or a group of users');
INSERT INTO `vulinoss`.`software_categories` (id,scname,description) VALUES (3,'System and administration utilities','System software designed to help analyze, configure, optimize or maintain a computer');
INSERT INTO `vulinoss`.`software_categories` (id,scname,description) VALUES (4,'Programming languages and development frameworks','Programming language, IDEs or platforms and framework that provides functionalities/solution to the particular problem area');
INSERT INTO `vulinoss`.`software_categories` (id,scname,description) VALUES (5,'Web and network utilities','Software that empowers the web (http servers, browsers, etc) and utilities that can be used related to computer network information gathering and analysis');
INSERT INTO `vulinoss`.`software_categories` (id,scname,description) VALUES (6,'Science and engineering applications','Scientific and engineering software');
INSERT INTO `vulinoss`.`software_categories` (id,scname,description) VALUES (7,'Other','Software that do not belong in any on the other categories');


# VulinOSS - Vulnerabilities in open-source systems
This project represents a dataset of vulnerabilities in open source projects, as published in Mining Software Repositories 2018 (MSR) conference.  

This ***README*** file presents how researchers can use this repository for:
 * importing the already existing dataset of vulnerabilities or,
 * using the provided source code to build the dataset from scratch. 

## Import the VulinOSS dataset
The *dataset* directory contains the SQL dump of the VulinOSS database. It's a self-contained file that includes the db schema and thus, it can be directly restored in one step.

## Build the dataset from scratch
The *src* directory contains the python scripts and the necessary data *.csv* for generating the VulinOSS dataset. 

The prerequisites for running the analysis are the following: 
* [Python 3](https://www.python.org/downloads/)
* (For Windows users) a Unix-like command-line interface like [Cygwin](https://cygwin.com/) or [Git Bash](https://git-for-windows.github.io/) is required.  
* [Perl](https://www.perl.org/)
* Count Lines of Code [(cloc)](https://github.com/AlDanial/cloc), a tool that counts blank lines, comment lines, and physical lines of source code in many programming languages. The perl executable should be stored under the following path ```lib/cloc.pl``` (create the *lib* directory if it doesn't exist)

Moreover, the following python modules are also required:
 * pymysql
 * colorama
 * codecs

### Generate the dataset and populate the database
To generate the VulinOSS dataset the following steps are required:
* Generate the VulinOSS db schema with the *schema_generator.sql* that is located in the *src/data* directory. 
* Clone locally the projects repositories. The *repo_downloader.sh* located in the *src/vulinoss* directory, automates this process by giving the *highest_cve_rated_oss.csv* as an input. Note that, if you execute this step manually, the local repo directory should have as a name a substring of the repository's URL (with the **/** symbols replace by **_**). For example, the https://github.com/owncloud/core.git should be stored as ***owncloud_core.git***
* Execute the python script responsible for parsing the NVD json files and storing the matches to the database requires the following arguments. Note that the db credentials must be changed in the ***nvd_json_parser.py*** script. 
	
        usage: nvd_json_parser.py [-h] [-m PROJECT_NAME_MAPPING] [-w]
                                  [-cb CONNECT_TO_CODE_BASE]
                                  cve_feed_directory oss_list

        positional arguments:
          cve_feed_directory    The directory which contains the JSON feed files
          oss_list              The csv with the most vulnerable open source systems

        optional arguments:
          -h, --help            show this help message and exit
          -m  --project_name_mapping PROJECT_NAME_MAPPING
                                The csv file that matches alternative project names to
                                their main names
          -w, --write_to_db     Writes to the database
          -cb  --connect_to_code_base CONNECT_TO_CODE_BASE
                                Scans the local repositories for connecting NVD
                                versions to repository snapshots

* Finally, if *-cb* was used in the previous step you can retrieve code metrics for every project release by executing the following python script:
	
        usage: code_metrics_retriever.py [-h] [-w WRITE_TO_FILE]
                                 oss_list repository_root_directory

        positional arguments:
          oss_list              The csv with the list of the projects to be retrieved
                                from the database and analyzed
          repository_root_directory
                                The root directory that contains the downloaded
                                repositories

        optional arguments:
          -h, --help            show this help message and exit
          -w, --write_to_file WRITE_TO_FILE
                                The output csv file
Note that this step creates sql insert statements and does not store the information directly to the database. 

## License
<a rel="license" href="http://creativecommons.org/licenses/by/4.0/"><img alt="Creative Commons Licence" style="border-width:0" src="https://i.creativecommons.org/l/by/4.0/88x31.png" /></a><br />This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/4.0/">Creative Commons Attribution 4.0 International License</a>.

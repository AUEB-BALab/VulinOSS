import json
import argparse
import os
import sys
import pymysql as db_connector
import codecs

from colorama import Fore, Back, Style

from cve import CVE
from project import Project, ProjectList
from repo_history_analyzer import RepoHistoryAnalyzer

parser = argparse.ArgumentParser()
parser.add_argument("cve_feed_directory", 
    help="The directory which contains the JSON feed files")
parser.add_argument("oss_list",
    help="The csv with the most vulnerable open source systems")
parser.add_argument("-m", "--project_name_mapping", 
    help="The csv file that matches alternative project names to their main names")
parser.add_argument("-w", "--write_to_db", action='store_true',
    help="Writes to the database")
parser.add_argument("-cb", "--connect_to_code_base", 
    help="Scans the local repositories for connecting NVD versions to repository snapshots")
args = parser.parse_args()


def get_repositories(a_dir):
    return [repo for repo in os.listdir(a_dir)
        if os.path.isdir(os.path.join(a_dir, repo))]


def match_local_to_repo(repo, repo_full_path, project_list):
    for project in project_list.projects:
        if project.repo_url.endswith(repo.replace("_", "/", 100)):
            project.local_repo_dir = repo_full_path.replace("\\","/",100)
            # print("\tFound match: {}::{}".format(project.repo_url,project.local_repo_dir)) #DEBUG
            return
    print(Fore.RED +"\t\tERROR : Didn't match to any of the NVD projects {}".format(repo) + Style.RESET_ALL)


# assigning ci arguments
json_directory = args.cve_feed_directory
json_file_list = os.listdir(json_directory)
# reading the project list
nvd_project_list_file = args.oss_list
nvd_project_list_lines = [line.strip() for line in open(nvd_project_list_file, 'r')]
nvd_project_list = {}
for line in nvd_project_list_lines:
    fields = line.split(';')
    nvd_project_list[fields[0]] = fields[1:]

nvd_project_name_mapping = {}
if args.project_name_mapping:
    nvd_project_name_mapping_file = args.project_name_mapping

    # Read the mapping file and populate the related dictionary 
    print("Reading NVD project name mapping file {}".format(nvd_project_name_mapping_file))
    nvd_project_name_mapping_lines = [line.strip() for line in open(nvd_project_name_mapping_file, 'r')]
    for line in nvd_project_name_mapping_lines:
        fields = line.split(';')
        nvd_project_name_mapping[fields[0]] = fields
    print("\tFound {} mappings".format(len(nvd_project_name_mapping_lines)))


cve_list = set()
rejected_cves = set()
project_list = ProjectList()
project_id = 0 # counter used as a project uid
for json_file_name in json_file_list:
    json_file_path = os.path.join(json_directory, json_file_name)
    print("Parsing json file :: {}".format(json_file_path), flush=True)
    # parsed_json = json.load(open(json_file_path))
    parsed_json = json.load(codecs.open(json_file_path, 'r', 'utf-8-sig'))
    for cve_items in parsed_json['CVE_Items']:
        cve_entry = cve_items['cve']
        # stores the CVE-XXXX-XXXX unique id
        cve_id = cve_entry['CVE_data_meta']['ID']
        # print(cve_id) # DEBUG
        # Ignore CVEs that are marked as REJECTED
        if "** REJECT **" in cve_entry['description']['description_data'][0]['value']:
            # print("\tSkipped due to marked as REJECTED.") # DEBUG
            continue

        cve = CVE()
        ### FIXME :: Refactor, the initialization should be performed in the Constructor, not here
        # assings the previously retrieved cve-id
        cve.id = cve_id
        # Some CVEs are missing most of their details. Skip them
        vendors = cve_entry['affects']['vendor']['vendor_data']
        if len(vendors) == 0:
            rejected_cves.add(cve_id)
            # print("Broken CVE: {}".format(cve_id))
            continue
        # assigns the CVE's description
        cve.description = cve_entry['description']['description_data'][0]['value']
        cve.description = cve.description.replace("'","",1000)
        # stores the CWE-XXXX unique id or NVD-CWE-Other/NVD-CWE-noinfo if it does not exist
        cve.cwe = cve_entry['problemtype']['problemtype_data'][0]['description'][0]['value'].replace("CWE-","",2)
        # assigns the published date
        cve.published_date = cve_items['publishedDate']
        # assigns the modified date
        cve.modified_date = cve_items['lastModifiedDate']

        # cvssV2 metrics
        impact_metrics = cve_items['impact']['baseMetricV2']
        cve.cvssV2_vector_string = impact_metrics['cvssV2']['vectorString']
        cve.cvssV2_access_vector = impact_metrics['cvssV2']['accessVector']
        cve.cvssV2_access_complexity = impact_metrics['cvssV2']['accessComplexity']
        cve.cvssV2_authentication = impact_metrics['cvssV2']['authentication']
        cve.cvssV2_confidentiality_impact = impact_metrics['cvssV2']['confidentialityImpact']
        cve.cvssV2_integrity_impact = impact_metrics['cvssV2']['integrityImpact']
        cve.cvssV2_availability_impact = impact_metrics['cvssV2']['availabilityImpact']
        cve.cvssV2_base_score = impact_metrics['cvssV2']['baseScore']
        # severity metrics
        cve.severity = impact_metrics['severity']
        cve.exploitation_score = impact_metrics['exploitabilityScore']
        cve.impact_score = impact_metrics['impactScore']
        cve.obtain_all_privilege = impact_metrics['obtainAllPrivilege']
        cve.obtain_user_privilege = impact_metrics['obtainUserPrivilege']
        cve.obtain_other_privilege = impact_metrics['obtainOtherPrivilege']
        if  'userInteractionRequired' in impact_metrics:
            cve.user_interaction_required = impact_metrics['userInteractionRequired']
        cve_list.add(cve)
        ## Assigning to Project ## 
        vendors = cve_entry['affects']['vendor']['vendor_data']
        # if len(vendors) > 1: # DEBUG
        #     print(cve_id) # DEBUG
        for vendor in vendors:
            vendor_name = vendor['vendor_name']
            # remove the '
            vendor_name = vendor_name.replace("'","")

            products = vendor['product']['product_data']
            for product in products:
                product_name = product['product_name']
                # remove '
                product_name = product_name.replace("'","",20)

                comparison_string = "%s:%s" % (vendor_name, product_name)
                #TODO move the mapping to a function
                # print("\tChecking name {}.".format(comparison_string)) # DEBUG
                for key in nvd_project_name_mapping:
                    if comparison_string in nvd_project_name_mapping[key]:
                        vendor_name = key.split(':')[0]
                        product_name = key.split(':')[1]
                # if len(vendors) > 1:# DEBUG
                #     print("\tProduct name: {}".format(product_name))# DEBUG

                # Check if product is in the oss most vulnerable list. If not then discard.
                comparison_string = "%s:%s" % (vendor_name, product_name)
                if comparison_string not in nvd_project_list:
                    # print("Project {} is not in the list. DISCARDED.".format(comparison_string))
                    continue

                if not project_list.projectInList(vendor_name,product_name):
                    # print("New project: {}:{}".format(vendor_name,product_name))
                    project_id += 1 # increase the counter
                    project = Project(project_id,vendor_name,product_name)
                    project.repo_url = nvd_project_list[comparison_string][0] 
                    project.website = nvd_project_list[comparison_string][1]
                    project.repo_type = nvd_project_list[comparison_string][2]
                    project.commit_reference = nvd_project_list[comparison_string][3]
                    project.software_type = False
                    if nvd_project_list[comparison_string][4] == 'tag' or nvd_project_list[comparison_string][4] == 'branch':
                        project.software_type = True
                    # //TODO Parse and add the versions here
                    project_list.add(project)
                else:
                    project = project_list.get(vendor_name,product_name)
                    # print("Retrieved project {}:{}".format(project.vendor, project.name))

                product_versions = product['version']['version_data']
                for version in product_versions:
                    version_value = version['version_value']
                    # //TODO: create a counter that will operate as a project release uid
                    project.addVulnerability(version_value,cve_id)
                    # print(version_value)
print("Skipped {} cves.".format(len(rejected_cves)))
# FIXME: move the insertion to db code to the appropriate classes. Keep only the db connection initialization here.

# connecting project versions to repository snapshots
if args.connect_to_code_base:
    local_repos_root_directory = args.connect_to_code_base
    print("Looking for projects in directory: %s" % local_repos_root_directory)
    local_repos = get_repositories(local_repos_root_directory)
    for repo in local_repos:
        repo_full_path = os.path.join(local_repos_root_directory, repo)
        # print("Checking if repo exists :: {}".format(repo_full_path))
        match_local_to_repo(repo, repo_full_path, project_list)
    repo_history_analyzer = RepoHistoryAnalyzer()
    for project in project_list.projects:
        if project.local_repo_dir:
            repo_history_analyzer.analyze(project)
        else:
            # print("No match found for {} ::")
            # project.print()
            pass


if args.write_to_db:
    # db = MySQLdb.connect(host= "localhost",
    db = db_connector.connect(host= "localhost",
                  user="root",
                  # passwd="mysql@d77c02",
                  passwd="",
                  db="vulinoss")
    cursor = db.cursor()
    print("Storing CVEs to database", flush=True)
    # Storing CVEs to DB
    for cve in cve_list:
       cve.writeCVEtoDB(db,cursor)
    # Storing projects to DB
    project_list.insertIntoDB(db,cursor)

    # disconnect from server
    db.close()

# project_list.print()

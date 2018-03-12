from colorama import Fore, Back, Style

from utility import Utility
from abstract_analyzer import Analyzer

class NVDMatchingAnalyzer(Analyzer):

    def __init__(self, project):
        super().__init__(project)


    def analyze(self, nvd_projects=[]):
        self.match_dir_to_nvd_project(nvd_projects)


    def match_dir_to_nvd_project(self, nvd_projects):
        print("\tMatching %s to NVD project-list..." % self.project.name, flush=True) #DEBUG
        matched = False
        for nvd_entry in nvd_projects:
            nvd_repo_link = nvd_entry.split(';')[2]
            # print("NVD project: %s" % nvd_repo_link)
            if project.repo_url.endswith(repo.replace("_", "/", 5)):
                print("\t\tFound match {}::{}}".format(project.repo_url, repo.replace("_", "/", 5))) #DEBUG
                self.parse_nvd_string(nvd_entry)
                matched = True
                break
        if not matched: #DEBUG
            print(Fore.RED +"\t\tERROR : Didn't match to any of the NVD projects" + Style.RESET_ALL) # DEBUG


    def parse_nvd_string(self, nvd_string):
        nvd_fields = nvd_string.split(';')
        # print(nvd_fields) # DEBUG
        if len(nvd_fields) == 4:
            self.project.nvd_name = nvd_fields[0]
            self.project.number_of_vulnerabilites = nvd_fields[1]
            self.project.repository_link = nvd_fields[2]
            self.project.project_url = nvd_fields[3]
            self.detect_cvs()
        else:
            print("ERROR on parsing the nvd_string %s %s" % (nvd_string, nvd_fields))

    def detect_cvs(self):
        # print("\trepo link :: {}".format(self.project.repository_link))
        repo_link = self.project.repository_link
        if any(ext in repo_link for ext in [".git","git.","git:"]):
            self.project.cvs_type = "Git"
        elif any(ext in repo_link for ext in [".svn","svn.","svn:"]):
            self.project.cvs_type = "Subversion"
        elif any(ext in repo_link for ext in [".hg","hg.","/hg/","bitbucket."]):
            self.project.cvs_type = "Mercurial"
        else:
            print("## ERROR ## didn't recognise CVS type in : {}".format(repo_link))
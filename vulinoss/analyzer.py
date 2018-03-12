import subprocess
import os
import re
import sys
import urllib.request
import io
from colorama import Fore, Back, Style
from tempfile import NamedTemporaryFile

from oss_project import OSSProject
from unit_test_analyzer import TestAnalyzer

"""The class that provide all analysis functions"""
class Analyzer(object):


    def __init__(self, repository):
        self.repository = repository
        self.log_file = "cloc_error_log.txt"


    def match_dir_to_nvd_project(self, nvd_projects):
        print("\tMatching %s to NVD project-list..." % self.repository.name, flush=True) #DEBUG
        matched = False
        for nvd_entry in nvd_projects:
            nvd_repo_link = nvd_entry.split(';')[2]
            # print("NVD project: %s" % nvd_repo_link)
            if nvd_repo_link.endswith(self.repository.name.replace("_", "/", 5)):
                print("\t\tFound match: %s" % nvd_repo_link) #DEBUG
                matched = True
                self.parse_nvd_string(nvd_entry)
                return True
                break
        if not matched: #DEBUG
            print(Fore.RED +"\t\tERROR : Didn't match to any of the NVD projects" + Style.RESET_ALL) # DEBUG
            return False
            # print(Style.RESET_ALL +"\r")


    def parse_nvd_string(self, nvd_string):
        nvd_fields = nvd_string.split(';')
        # print(nvd_fields)
        if len(nvd_fields) == 4:
            self.repository.nvd_name = nvd_fields[0]
            self.repository.number_of_vulnerabilites = nvd_fields[1]
            self.repository.repository_link = nvd_fields[2]
            self.repository.project_url = nvd_fields[3]
        else:
            print("ERROR on parsing the nvd_string %s %s" % (nvd_string, nvd_fields))

        # self.repository.nvd_name, self.repository.number_of_vulnerabilites, self.repository.repository_link, self.repository.project_url = nvd_string.split(';')


    def retrieve_alexa_ranking(self):
        alexa_site_info_url = "https://www.alexa.com/siteinfo/"
        print("\tFetching alexa ranking...")
        page = urllib.request.urlopen(alexa_site_info_url + self.repository.project_url, data = None)
        ranking = self.parse_alexas_content(str(page.read()))
        self.repository.alexa_ranking = ranking
        print("\t\tRanking = %s" % self.repository.alexa_ranking)


    def parse_alexas_content(self, content):
        keyword = '"global":'
        if keyword not in content:
            return 0
        else:
            start_index = content.find(keyword) + len(keyword)
            content = content[start_index:]
            end_index = content.find('}')
            ranking = content[:end_index]
            return int(ranking) if ranking != "false" else 0


    def get_pr_language(self):
        print("\tDetecting main programming language and coding metrics...", flush=True)
        
        if not self.repository.has_been_matched():
            print("\t\t\tSkipped. [not matched to nvd]")
            return

        cloc_command = "../lib/cloc.pl"
        with open(self.log_file, 'a') as log:
            proc = subprocess.Popen(["perl", cloc_command, "--csv", self.repository.path], stdout=subprocess.PIPE, stderr=log)
            cloc_output = proc.stdout.read().decode(encoding='UTF-8')
            self.parse_cloc_output(cloc_output)

        self.calculate_vulnerabilities_ratio()


    def parse_cloc_output(self, cloc_output):
        valid_languages = ["ActionScript","Ada","Ant","ASP","ASP.NET","AspectJ","Assembly","awk",
        "Blade","BourneAgainShell","BourneShell","BrightScript","C","CShell","C#","C++","C/C++Header",
        "CMake","COBOL","CoffeeScript","Crystal","CSS","Cython","D","DOSBatch","Erlang","F#","F#Script",
        "Fortran77","Fortran90","Fortran95","Go","Grails","Groovy","Haskell","HTML","Java","JavaScript",
        "JavaServerFaces","JSP","Kermit","Lisp","Lua","MATLAB","ObjectiveC","ObjectiveC++","Pascal",
        "Perl","PHP","PowerShell","Prolog","Python","R","Ruby","RubyHTML","Rust","Scala","Smalltalk",
        "TypeScript","VisualBasic","zsh"]

        if not self.repository.has_been_matched():
            return

        # crop output
        start = "files,language,blank,comment,code"
        cloc_output = cloc_output[cloc_output.index(start):].split("\n")[1:]
        # print(cloc_output) #DEL

        # Creating a dictionary with the language and its metrics
        lang_metrics = {}
        for line in cloc_output:
            cloc_metrics = line.split(",")
            if len(cloc_metrics) == 5:       
                lang = cloc_metrics[1]
                lang_metrics[lang] = [
                    int(cloc_metrics[0]),
                    int(cloc_metrics[2]),
                    int(cloc_metrics[3]),
                    int(cloc_metrics[4])]
                # print(lang_metrics) # DEBUG
            else:
                # print("Invalid cloc line --> %s" % cloc_metrics) # DEBUG
                pass

        # print("Languages: %d" % len(lang_metrics))
        # Scanning for the first valid language
        for lang in lang_metrics:
            # print("Scanning %s" % lang)
            if lang in valid_languages:
                # print("Found valid language: %s" % lang)
                self.repository.main_programming_language = lang
                self.repository.projects_size = lang_metrics[lang][0]
                self.repository.blank_loc = lang_metrics[lang][1]
                self.repository.comment_loc = lang_metrics[lang][2]
                self.repository.loc = lang_metrics[lang][3]
                # self.repository.print_cloc_metrics() # DEBUG
                # Merging C/C++Header with C or C++
                conditions = ["C", "C++"]
                if any(conditions) and "C/C++ Header" in lang_metrics:
                    # print("Adding Headers to C or C++")
                    c_headers_name = "C/C++ Header"
                    self.repository.projects_size += lang_metrics[c_headers_name][0]
                    self.repository.blank_loc += lang_metrics[c_headers_name][1]
                    self.repository.comment_loc += lang_metrics[c_headers_name][2]
                    self.repository.loc += lang_metrics[c_headers_name][3]
                    # self.repository.print_cloc_metrics() # DEBUG
                break
        
        # self.repository.print_cloc_metrics() # DEBUG


    def calculate_vulnerabilities_ratio(self):
        print("\tCalculating vulnerabilities ratio...", flush=True)
        self.repository.vulnerabilities_ratio = int(self.repository.number_of_vulnerabilites)/int(self.repository.loc)
        # print("\t\t%s/%s=%f" % (self.repository.number_of_vulnerabilites, self.repository.loc, self.repository.vulnerabilities_ratio))


    def discover_ci(self):
        print("\tSearching for Continous Integration config file...", flush=True)

        if not self.repository.has_been_matched():
            print("\t\t\tSkipped. [not matched to nvd]")
            return

        ci_providers = {".travis.yml":"Travis",
                        "appveyor.yml":"AppVeyor",
                        ".magnum.yml":"Magnum",
                        "circle.yml":"Circle",
                        ".hound.yml":"Hound",
                        "shippable.yml":"Shippable",
                        "solano.yml":"Solano",
                        "wercker.yml":"Wercker"}
        found = False # DEBUG
        for ci_type in ci_providers:
            ci_config_file = os.path.join(self.repository.path, ci_type)
            # print("Checking ci: %s" % ci_config_file) #DEBUG
            if os.path.exists(ci_config_file) and os.path.getsize(ci_config_file) > 0:
                print("\t\tFound : %s" % ci_config_file)
                self.repository.ci = True
                self.repository.ci_type = ci_providers[ci_type]
                found = True
                break

        if not found:
            print("\t\tWARNING: Couldn't find CI configuration file in the project")


    def get_test_folders(self):
        print("\tSearching for test folders with name ['test', 'tests', 'spec']...", flush=True) # DEBUG
        
        if not self.repository.has_been_matched():
            print("\t\t\tSkipped. [not matched to nvd]")
            return

        test_folder_exists = False
        test_folders = set()
        for root, directories, files in os.walk(self.repository.path):
            for directory in directories:
                dir_path = os.path.join(root, directory)
                for test_dir in ['test', 'tests', 'spec']:
                    if (os.sep + test_dir + os.sep) in (dir_path + os.sep):
                        test_folder_exists = True
                        test_folders.add(dir_path)

        if not test_folder_exists:
            print("\t\tWARNING: No test folders for this project")
        else:
            print("\t\tFolders found")

        return test_folders


    def get_test_files(self, test_folders):
        print("\tSearching for files that contain test code...", flush=True) # DEBUG
        
        if not self.repository.has_been_matched():
            print("\t\t\tSkipped. [not matched to nvd]")
            return

        test_discoverer = TestAnalyzer.get_test_discoverer(self.repository.main_programming_language)
        
        test_files = set()
        # Select all files in "test" folders
        for test_folder in test_folders:
            # print("Loading files from %s" % test_folder)
            for root, directories, files in os.walk(test_folder):    
                for filename in files:
                    test_files.add(os.path.join(root,filename))
                    # print("Checking file %s" % filename)
                    # for language_extension in test_discoverer.extensions:
                    #     if filename.endswith(language_extension):
                            # test_files.add(os.path.join(root,filename))
        test_files_size = len(test_files)
        if test_files_size > 0:
            print("\t\tTest folders contained files.")
        else:
            print("\t\tWARNING: No files detected in the test folders.")

        # If test_discoverer exists
        if test_discoverer is not None:
            for root, directories, files in os.walk(self.repository.path):
                for filename in files:
                    file_path = os.path.join(root,filename)
                    with open(file_path, 'r', encoding = "ISO-8859-1") as myfile:
                        data = myfile.read()

                    for pattern in test_discoverer.test_frameworks:
                        searchObj = re.search(pattern, data)
                        if searchObj:
                            test_files.add(file_path)

        if len(test_files) > test_files_size:
            print("\t\tSingle testing files added.")
        else:
            print("\t\tWARNING: No single testing files detected.")
        # Select all files that satisfy the pr language pattern for testing frameworks
        return test_files


    def parse_test_files(self, files):
        command = 'perl ../lib/cloc.pl --csv '
        if files:
            # Using temporary file to overcome the character limit in bash
            tempfile = NamedTemporaryFile(delete=False)
            with open(tempfile.name,'w',encoding='utf-8') as _tempfile:
                try:
                    for _file in files:
                        _tempfile.write('{0}\n'.format(_file))
                except:
                    print(Fore.RED +"\t\t\tEncoding error in testing file. skipped." + Style.RESET_ALL) # DEBUG
                    pass

            command += '--list-file={0}'.format(tempfile.name)
            # print(command) #DEBUG

            process = subprocess.Popen(
                command, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )

            (out, err) = [x.decode() for x in process.communicate()]

            lines = [
                line for line in out.split('\n') if len(line.strip('\n')) != 0
            ]

            # parse the results from the cloc execution
            self.cloc_test_results(lines)


    ### Parses the output of 
    def cloc_test_results(self, lines):
        print("\t\t\tMain language : %s" % self.repository.main_programming_language)
        for line in lines[4:]: # first result line is different than the one in the main cloc
            cloc_metrics = line.split(",")
            projects_size = int(cloc_metrics[0])
            main_programming_language = cloc_metrics[1]
            blank_loc = int(cloc_metrics[2])
            comment_loc = int(cloc_metrics[3])
            loc = int(cloc_metrics[4])
            # print("\t\t\tMetrics=%s\n\t\t\tpr_size=%d, lang=%s, blank=%d, comment=%d, loc=%d" % # DEBUG
            # (cloc_metrics, projects_size, main_programming_language, blank_loc, comment_loc, loc)) # DEBUG
            if main_programming_language == self.repository.main_programming_language:
                print("\t\t\tFound matching functional and testing code. Setting teting metrics.")
                self.repository.test_projects_size = int(cloc_metrics[0])
                self.repository.test_main_programming_language = cloc_metrics[1]
                self.repository.test_blank_loc = int(cloc_metrics[2])
                self.repository.test_comment_loc = int(cloc_metrics[3])
                self.repository.test_loc = int(cloc_metrics[4])


    def calculate_testing_ratio(self):
        print("\tCalculating testing ratio...", flush=True) # DEBUG

        if not self.repository.has_been_matched():
            print("\t\t\tSkipped. [not matched to nvd]")
            return
        self.repository.testing_ratio = self.repository.test_loc/self.repository.loc
        # self.repository.print_test_cloc_metrics()


    def calculate_documentation(self):
        print("\tCalculating documentation ratio...", flush=True) # DEBUG

        if not self.repository.has_been_matched():
            print("\t\t\tSkipped. [not matched to nvd]")
            return

        self.repository.documentation_ratio = self.repository.comment_loc/self.repository.loc


    def count_test_code(self):
        # get test folders
        test_folders = self.get_test_folders()
        # print(test_folders)
        test_files = self.get_test_files(test_folders)

        self.parse_test_files(test_files)
        self.calculate_testing_ratio()
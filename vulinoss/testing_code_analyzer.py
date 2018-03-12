import os
import re
from colorama import Fore, Back, Style

from utility import Utility
from abstract_analyzer import Analyzer

from unit_test_analyzers.c import CTestDiscoverer
from unit_test_analyzers.cpp import CPPTestDiscoverer
from unit_test_analyzers.csharp import CSharpTestDiscoverer
from unit_test_analyzers.java import JavaTestDiscoverer
from unit_test_analyzers.javascript import JavaScriptTestDiscoverer
from unit_test_analyzers.objectivec import ObjectiveCTestDiscoverer
from unit_test_analyzers.php import PHPTestDiscoverer
from unit_test_analyzers.python import PythonTestDiscoverer
from unit_test_analyzers.ruby import RubyTestDiscoverer

class TestingCodeAnalyzer(object):
    test_discoverers = [
        CTestDiscoverer(),
        CPPTestDiscoverer(),
        CSharpTestDiscoverer(),
        JavaTestDiscoverer(),
        JavaScriptTestDiscoverer(),
        ObjectiveCTestDiscoverer(),
        PHPTestDiscoverer(),
        PythonTestDiscoverer(),
        RubyTestDiscoverer()
    ]


    def __init__(self, project):
        self.project = project

    def analyze(self):
        test_folders = self.detect_test_folders()
        test_files = self.detect_test_files(test_folders)
        if test_files:

            #print("\tSearching for test folders with name ['test', 'tests', 'spec']...", flush=True) # DEBUG
            #print("### Test files {} ### :: {}".format(len(test_files), test_files))
            cloc_output = Utility.run_cloc(self.project.local_repo_dir, test_files)
            test_metrics = Utility.parse_cloc_output(cloc_output)
            # self.calculate_test_results(test_metrics)
            # self.calculate_testing_ratio()
            return test_metrics


    def detect_test_folders(self):
        # print("\tSearching for test folders with name ['test', 'tests', 'spec']...", flush=True) # DEBUG
        test_folder_exists = False
        test_folders = set()
        for root, directories, files in os.walk(self.project.local_repo_dir):
            for directory in directories:
                dir_path = os.path.join(root, directory)
                for test_dir in ['test', 'tests', 'spec']:
                    if (os.sep + test_dir + os.sep) in (dir_path + os.sep):
                        test_folder_exists = True
                        if os.path.exists(dir_path):
                            test_folders.add(dir_path)
                        else:
                            pass
                            # print("Test folder skipped :: %s" % dir_path) # DEBUG
        if not test_folder_exists:
            # print("\t\tNo test folders for this project")
            pass

        return test_folders


    def detect_test_files(self, test_folders):
        # print("\tSearching for files that contain test code...", flush=True) # DEBUG
        for test_discoverer in TestingCodeAnalyzer.test_discoverers:
            # print("Using test discoverer:: {}".format(test_discoverer))
        # test_discoverer = TestingCodeAnalyzer.get_test_discoverer(self.project.main_programming_language)
        
            test_files = set()
            # Select all files in "test" folders
            for test_folder in test_folders:
                # print("Loading files from %s" % test_folder)
                for root, directories, files in os.walk(test_folder):    
                    for filename in files:
                        new_test_file = os.path.join(root,filename)
                        if os.path.exists(new_test_file):
                            test_files.add(new_test_file)
                        else:
                            pass
                            # print("Test file skipped :: %s" % new_test_file) # DEBUG

            test_files_size = len(test_files)
            # if test_files_size > 0:
            #     print("\t\tTest folders contained files.")
            # else:
            #     print("\t\tWARNING: No files detected in the test folders.")

            # If test_discoverer exists
            if test_discoverer is not None:
                for root, directories, files in os.walk(self.project.local_repo_dir):
                    for filename in files:
                        file_path = os.path.join(root,filename)
                        if os.path.exists(file_path) and all(exclude_dir not in file_path for exclude_dir in [".git",".svn",".hg"]):
                            with open(file_path, 'r', encoding = "ISO-8859-1") as myfile:
                                data = myfile.read()

                            for pattern in test_discoverer.test_frameworks:
                                searchObj = re.search(pattern, data)
                                if searchObj:
                                    test_files.add(file_path)
                        else:
                            pass
                            # print("Test file skipped 2 :: %s" % file_path)

            if len(test_files) > test_files_size:
                # print("\t\tSingle testing files added.") # DEBUG
                pass
            else:
                # print("\t\tWARNING: No single testing files detected.") # DEBUG
                pass
            # Select all files that satisfy the pr language pattern for testing frameworks
            # for file in test_files:
            #     print("### Test file :: {}".format(file))
        return test_files


    # def calculate_test_results(self, test_metrics):
    #     if self.project.main_programming_language in test_metrics:
    #         main_lang_test_metrics = test_metrics[self.project.main_programming_language]
    #         # print(main_lang_test_metrics)
    #         if main_lang_test_metrics:
    #             self.project.test_projects_size = int(main_lang_test_metrics[0])
    #             self.project.test_main_programming_language = self.project.main_programming_language
    #             self.project.test_blank_loc = int(main_lang_test_metrics[1])
    #             self.project.test_comment_loc = int(main_lang_test_metrics[2])
    #             self.project.test_loc = int(main_lang_test_metrics[3])   
    #     else:
    #         print("\t\tNo testing code in the project for the language %s" % self.project.main_programming_language)         
    #         pass
        

    # def calculate_testing_ratio(self):
    #     print("\tCalculating testing ratio...", flush=True) # DEBUG
    #     self.project.testing_ratio = self.project.test_loc/self.project.loc
    #     # self.project.print_test_cloc_metrics() # DEBUG


    # def get_test_discoverer(language):
    #     # print("\tCreating Test code analyzer for %s" % language)
    #     if language  == "C":
    #         return CTestDiscoverer()
    #     elif language == "C++":
    #         return CPPTestDiscoverer()
    #     elif language == "C#":
    #         return CSharpTestDiscoverer()
    #     elif language == "Java":
    #         return JavaTestDiscoverer()
    #     elif language == "JavaScript":
    #         return JavaScriptTestDiscoverer()
    #     elif language == "Objective C":
    #         return ObjectiveCTestDiscoverer()
    #     elif language == "PHP":
    #         return PHPTestDiscoverer()
    #     elif language == "Python":
    #         return PythonTestDiscoverer()
    #     elif language == "Ruby":
    #         return RubyTestDiscoverer()
    #     else:
    #         print(Fore.RED +"\t\tWARNING : There is no analyzer for %s" % language + Style.RESET_ALL)
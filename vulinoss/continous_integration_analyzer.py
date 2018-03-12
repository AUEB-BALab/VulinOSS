import os

from abstract_analyzer import Analyzer

class ContinousIntegrationAnalyzer(Analyzer):

    """
    A dictionary with Continous Integration providers and their
    configuration files. 
    """
    ci_providers = {".travis.yml":"Travis",
                    "appveyor.yml":"AppVeyor",
                    ".magnum.yml":"Magnum",
                    "circle.yml":"Circle",
                    ".hound.yml":"Hound",
                    ".scrutinizer.yml":"Scrutinizer",
                    "shippable.yml":"Shippable",
                    "solano.yml":"Solano",
                    "wercker.yml":"Wercker"}	


    def __init__(self, project):
        super().__init__(project)


    def analyze(self):
        """
        Performs the steps for the analysis of the continous 
        integration configuration file detection.
        """
        result =  self.discover_ci()
        return result


    def discover_ci(self):
        # print("\tSearching for Continous Integration config file...", flush=True)

        found = False # DEBUG
        for root, directories, files in os.walk(self.project.local_repo_dir):
            for file in files:
                for ci_type in ContinousIntegrationAnalyzer.ci_providers:
                    # if ci_type in file:
                        # print("potential ci {}".format(file))
                    if file.endswith(ci_type):
                        # print("\t\tFound : %s" % file)
                        return ContinousIntegrationAnalyzer.ci_providers[ci_type]

        
        # print("\t\tWARNING: Couldn't find CI configuration file for this version") 
        return ""
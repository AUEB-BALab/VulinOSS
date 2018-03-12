import os

from abstract_analyzer import Analyzer
from utility import Utility

class HistoryCheckoutAnalyzer(Analyzer):

    def __init__(self, project, year=2018):
        super().__init__(project)
        self.year = year
    

    def analyze(self):
        cvs = self.project.cvs_type
        print("\tReverting %s [%s] to a state before %s..." % (self.project.name, cvs, self.year), flush=True) #DEBUG

        if cvs == "Git":
            self.revert_git()
        elif cvs == "Subversion":
            self.revert_svn()
        elif cvs == "Mercurial":
            self.revert_hg()
        else:
            print("## ERROR ## repo_link : {}".format(repo_link))


    def revert_git(self):
        # print("\t\tReverting git...") #DEBUG
        git_revision_command = "git -C {} rev-list -n 1 --before=\"{}\" --all".format(self.project.path,self.year)
        revision = Utility.execute_process(git_revision_command)
        # print("\t\tChecked out revision {}.".format(revision))
        git_checkout = "git -C {} checkout {}".format(self.project.path, revision)
        result = Utility.execute_process(git_checkout)

    
    def revert_svn(self):
        # print("\t\tReverting svn...") #DEBUG
        svn_checkout = "svn update -r {} {}".format(self.year, self.project.path)
        result = Utility.execute_process(svn_checkout)
        # print("\t\t{}".format(result)) # DEBUG


    def revert_hg(self):
        # print("\t\tReverting hg...") #DEBUG
        hg_checkout = "hg update --clean --rev \"date(\'<{}\')\" -R {}".format(self.year, self.project.path)
        result = Utility.execute_process(hg_checkout)
        # print("\t\tRevision results :: {}".format(result)) # DEBUG

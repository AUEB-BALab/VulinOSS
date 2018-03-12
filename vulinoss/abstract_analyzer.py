from abc import ABC, abstractmethod
from project import Project

class Analyzer(ABC):

    def __init__(self, project):
        self.project = project
    
    @abstractmethod
    def analyze(self, run_for_period=False):
        pass
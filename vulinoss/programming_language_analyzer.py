from abstract_analyzer import Analyzer
from utility import Utility

class ProgrammingLanguageAnalyzer(Analyzer):

    """
    A list of languages that are considered as valid programming
    languages. Metrics from any other language are omitted. 
    """
    valid_languages = ["ActionScript","Ada","ASP","ASP.NET",
        "AspectJ","Assembly","Blade","BourneAgainShell",
        "BourneShell","BrightScript","C","CShell","C#","C++",
        "C/C++Header","CMake","COBOL","CoffeeScript","Crystal",
        "Cython","D","DOSBatch","Erlang","F#","F#Script",
        "Fortran77","Fortran90","Fortran95","Go","Grails",
        "Groovy","Haskell","Java","JavaScript","JavaServerFaces",
        "JSP","Lisp","Lua","MATLAB","ObjectiveC",
        "ObjectiveC++","Pascal","Perl","PHP","PowerShell",
        "Prolog","Python","R","Ruby","RubyHTML","Rust", "Swift",
        "Scala","Smalltalk","TypeScript","VisualBasic","zsh"]


    def __init__(self, project):
        super().__init__(project)


    def analyze(self):
        """
        Performs the steps for the analysis of the programming language 
        and its related metrics for the project.

        """
        print("\tDetecting main programming language and coding metrics...", flush=True)
        # self.project.print_cloc_metrics() # DEBUG
        cloc_output = Utility.run_cloc(self.project.path)
        lang_metrics = Utility.parse_cloc_output(cloc_output)
        self.populate_pr_language_metrics(lang_metrics)

        # self.project.print_cloc_metrics() # DEBUG


    def populate_pr_language_metrics(self,lang_metrics):
        """
        Populates the project's programming language metrics from a 
        given dictionary of metrics per programming languages, as produced
        by the cloc tool.

        The project's programming language metrics are those directly
        retrieved from the CLOC tool like the following:
            main_programming_language
            projects_size
            blank_loc
            comment_loc
            loc

        Parameters
        ----------
        lang : dictionary
            A dictionary with keys each retrieved programming language
            and the metrics for each language. ex:
            {'Python': [1882, 50066, 47903, 216764], 
             'PO File': [1136, 70500, 9752, 213272]}

        Returns
        -------
        
        """
        print("\tPopulating loc metrics...", flush=True)
        # Scanning for the first valid language
        for lang in lang_metrics:
            if lang in ProgrammingLanguageAnalyzer.valid_languages:
                # print("Found valid language: %s" % lang) # DEBUG
                self.project.main_programming_language = lang
                self.project.projects_size += lang_metrics[lang][0]
                self.project.blank_loc += lang_metrics[lang][1]
                self.project.comment_loc += lang_metrics[lang][2]
                self.project.loc += lang_metrics[lang][3]
                # self.project.print_cloc_metrics() # DEBUG
                # Merging C/C++Header with C or C++
                conditions = ["C", "C++"]
                if any(conditions) and "C/C++ Header" in lang_metrics:
                    # print("Adding Headers to C or C++")
                    c_headers_name = "C/C++ Header"
                    self.project.projects_size += lang_metrics[c_headers_name][0]
                    self.project.blank_loc += lang_metrics[c_headers_name][1]
                    self.project.comment_loc += lang_metrics[c_headers_name][2]
                    self.project.loc += lang_metrics[c_headers_name][3]
                    # self.project.print_cloc_metrics() # DEBUG
                break
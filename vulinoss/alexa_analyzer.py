import urllib.request

from abstract_analyzer import Analyzer

class AlexaAnalyzer(Analyzer):

    """
    The base url for retrieving the alexa ranking for a web-sit
    example: "https://www.alexa.com/siteinfo/google.com"
    """
    alexa_site_info_url = "https://www.alexa.com/siteinfo/"


    def __init__(self, project):
        super().__init__(project)


    def analyze(self):
        """
        Performs the steps for the analysis of the Alexa ranking 
        retrieval.
        """
        print("\tFetching alexa ranking...", flush=True)
        # retrieve the web page content the includes the ranking
        content = self.fetch_web_site_source()
        # parse the web-page's content for retrieving the ranking
        ranking = self.parse_alexas_content(content)
        # assign the ranking to the project's corresponfing field
        self.project.alexa_ranking = ranking
        print("\t\tRanking = %s" % self.project.alexa_ranking)


    def fetch_web_site_source(self):
        """
        Fetches the content of the web page that contains the 
        Alexa ranking for the specific project.

        The project's page ranking is retrived from a url created by 
        joining the alexa_site_info_url and the project's manually url
        retrived from the second execution parameter. Example:
        https://www.alexa.com/siteinfo/my-projects-url

        Exception
        ----------
        urllib.error.URLError 
            A urllib.error.URLError exception is produced and handled in
            case that the provided url is malformed. 

        Returns
        -------
        String : The string encoded content of the retrieved web-page or
        an emtpy string in case of an error.  
        """
        try:
            page = urllib.request.urlopen(AlexaAnalyzer.alexa_site_info_url + self.project.project_url, data = None)
            return str(page.read())
        except urllib.error.URLError as e:
            # TODO: Write the Exception in the log file
            print("Exception::Alexa:: %s" % e)
            return ""

    def parse_alexas_content(self, content):
        """
        Parses the content of a retrieved Alexa's ranking web-page
        and returns the ranking. 

        The global ranking of a web-page according to Alexa, is located
        in a JSON format right after the ["global":] key. Zero is returned
        in cases that Alexa has no data/or not enough data to rank the web-page  

        Parameters
        ----------
        content : String
            The content of the downloaded web-page in a String format

        Returns
        -------
        int : The ranking in an integer value format or zero (0) if the 
        ranking doesn't exist
        """
        keyword = '"global":'
        if keyword not in content:
            return 0
        else:
            start_index = content.find(keyword) + len(keyword)
            content = content[start_index:]
            end_index = content.find('}')
            ranking = content[:end_index]
            return int(ranking) if ranking != "false" else 0
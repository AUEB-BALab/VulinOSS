class PythonTestDiscoverer(object):
    def __init__(self):
        self.languages = ['Python']
        self.extensions = ['*.py']
        self.test_frameworks = [
            '((from|import)(\s)(django\.test))',
            '((from|import)(\s)(nose))',
            '((from|import)(\s)(unittest))'
            ]
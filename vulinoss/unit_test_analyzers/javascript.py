class JavaScriptTestDiscoverer(object):
    def __init__(self):
        self.languages = ['JavaScript']
        self.extensions = ['*.js']
        self.test_frameworks = [
            '(describe\()(.*)(function)'
            ]
class PHPTestDiscoverer(object):
    def __init__(self):
        self.languages = ['PHP']
        self.extensions = ['*.php']
        self.test_frameworks = [
            'PHPUnit_(Framework|Extensions_Database)_TestCase'
            ]
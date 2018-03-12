class JavaTestDiscoverer(object):
    def __init__(self):
        self.languages = ['Java']
        self.extensions = ['*.java']
        self.test_frameworks = [
            'import (org.junit|junit.framework)',
            'import org.testng'
            ]
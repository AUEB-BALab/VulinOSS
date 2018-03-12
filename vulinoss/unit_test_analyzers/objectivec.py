class ObjectiveCTestDiscoverer(object):
    def __init__(self):
        self.languages = ['Objective C']
        self.extensions = ['*.m', '*.h']
        self.test_frameworks = [
            'XCTest.h'
            ]
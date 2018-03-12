class CTestDiscoverer(object):
    def __init__(self):
        self.languages = ['C', 'C/C++ Header']
        self.extensions = ['.c', '.h']
        self.test_frameworks = [
            '#include <assert.h>',
            '#include "clar.h"',
            '(g_assert*|g_test*|GTest*)',
            '#include "picotest.h"'
        ]
class CPPTestDiscoverer(object):
    def __init__(self):
        self.languages = ['C++']
        self.extensions = ['.cc', '.C', '.cxx', '.c++',
                            '.hh', '.H', '.hxx', ".h++"]
        self.test_frameworks = [
            '#include <assert.h>',
            '(BOOST_TEST_ALTERNATIVE_INIT_API|boost/test/unit_test.hpp|'
            'boost/test/included/unit_test.hpp|BOOST_TEST_DYN_LINK)',
            '#include "catch.hpp"',
            '#include (<|")(gtest/)?gtest.h(>|")',
            '#include <stout/gtest.hpp>'
            ]
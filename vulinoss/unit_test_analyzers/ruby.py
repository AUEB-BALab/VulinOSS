class RubyTestDiscoverer(object):
    def __init__(self):
        self.languages = ['Ruby']
        self.extensions = ['*.rb']
        self.test_frameworks = [
            '(MiniTest::Unit::TestCase|Minitest::Test)',
            '(describe)(.*)(do)',
            'Test::Unit::TestCase'
            ]
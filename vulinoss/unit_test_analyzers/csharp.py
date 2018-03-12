class CSharpTestDiscoverer(object):
    def __init__(self):
        self.languages = ['C#']
        self.extensions = ['*.cs']
        self.test_frameworks = [
            'using NUnit.Framework;',
            'using Microsoft.VisualStudio.TestTools.UnitTesting;',
            'using Xunit;'
            ]
import pytest
import yaml
from remchk.schema import *


def init_test(filename='data/test.yml'):
    with open('data/test.yml', 'r') as f:
        d = yaml.load(f, Loader=yaml.FullLoader)
        size = len(d['vuls'])
        return d, size


class TestSchema:
    doc, size = init_test('data/test.yml')

    def test_LOGIN(self):
        assert validate(self.doc['login'], LOGIN) == {}

    def test_SETTINGS(self):
        assert validate(self.doc['settings'], SETTINGS) == {}

    @pytest.mark.parametrize('i', range(size))
    def test_VULS_REPORT(self, i):
        if 'report' in self.doc['vuls'][i]:
            assert validate(self.doc['vuls'][i]['report'], REPORT) == {}

    @pytest.mark.parametrize('i', range(size))
    def test_VULS_CHECK(self, i):
        assert validate(self.doc['vuls'][i]['check'], CHECK) == {}

    @pytest.mark.parametrize('i', range(size))
    def test_VULS_ATTACK(self, i):
        assert validate(self.doc['vuls'][i]['attack'], ATTACK) == {}

    @pytest.mark.parametrize('i', range(size))
    def test_VULS(self, i):
        assert validate(self.doc['vuls'][i], VULS) == {}

    def test_YAML(self):
        assert validate(self.doc, YAML) == {}

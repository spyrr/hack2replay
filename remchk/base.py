
from colorama import Fore, Style
import cerberus
import requests
import sys
import yaml
import remchk
import remchk.schema as schema
from pprint import pprint

EMJ_HOST = '🖥️'
EMJ_MEMO = '📝'
EMJ_LV3 = '✔️ '
EMJ_RESULT = '✏️'
EMJ_VUL = ''
EMJ_NVUL = ''
EMJ_VULN = f'{Fore.RED}❌{Style.RESET_ALL}'
EMJ_LV3 = '✔️ '
EMJ_NVULN = '✅'
EMJ_NVULN = f'{Fore.GREEN}✔️{Style.RESET_ALL}'


class Handler(dict):
    def __init__(self, _path='.'):
        pass

    def setup(self, _path: str):
      return self

    def try_all(self):
      pass

    def try_one(self, _id: str):
      pass

    def get_list(self):
      pass

    def load_from_file(self, _filename: str, allow_unknown=False):
        with open(_filename, 'r') as f:
            doc = yaml.load(f, Loader=yaml.FullLoader)
        self._validate_schema(doc, schema._YAML)

    def _validate_schema(self, _doc: dict, _schema: dict):
        v = cerberus.Validator(_schema)
        v.allow_unknown=allow_unknown

        if v.validate(_doc) != True:
            print(v.errors)
            sys.exit(-1)

    def _request(self, dataset, proxies={'http': 'http://127.0.0.1:8080'}):
        rq = requests.Request(**dataset)
        s = requests.Session()
        s.proxies.update(proxies)
        return s.send(rq.prepare())

    def _reporting(self, report):
        try:
            for o in report['report']['highlight']:
                name, value = o['name'], o['value']
                report[name] = report[name].replace(
                    value, f'{Fore.RED}{value}{Style.RESET_ALL}'
                )
        except: # KeyError : Skip highlighting
            pass

        details = [
            [EMJ_HOST, 'Host', report['hostname']],
            [EMJ_MEMO, 'Vulnerable URL', report['url']],
            [
                EMJ_MEMO, 'Parameters',
                report['params'] if 'params' in report else ''
            ],
            [EMJ_MEMO, 'Method', report['method']],
            [EMJ_MEMO, 'Status code', report['status_code']],
            [EMJ_RESULT, 'Result', report['reason']]
        ]

        if report['is_vulnerable'] == True:
            print(
                f'{EMJ_VULN} ' + 
                f'[{report["id"]}] ' + 
                f'{report["title"]} ' + 
                f'[{Fore.RED}{report["result"]}{Style.RESET_ALL}]'
            )
            for a1, a2, a3 in details:
                print(f'\t{a1} {a2}: {a3}')
            print()
        else:
            print(
                f'{EMJ_NVULN} ' + 
                f'[{report["id"]}] ' + 
                f'{report["title"]} ' + 
                f'[{Fore.GREEN}{report["result"]}{Style.RESET_ALL}]'
            )


if __name__ == '__main__':
    d = Handler()
    d.load_from_file('tests/test.yml')
    pprint(d.doc, depth=2, indent=2)

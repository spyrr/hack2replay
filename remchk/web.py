import json
import remchk.base as base
import remchk.schema as schema
import sys


class Handler(base.Handler):
    def __init__(self, _path='.'):
        self.doc = None
        self.cred = {} # hostname : cookie
        self.load_from_file(_path, True)
        self._loading()

    def print_schema(self):
        print(json.dumps(schema.YAML, indent=2))

    def login(self, key):
        self._login(key)

    def _login(self, key):
        # TODO: basic auth
        # TODO: CSRF token
        doc = self.doc['login'][key]
        dataset = dict(
            method=doc['method'].upper(),
            url=doc['url']
        )
        dataset[doc['params']['type']] = doc['params']['data']
        rs = self._request(dataset)

        if rs.status_code != doc['success']['code']:
            return False

        for o in doc['success']['then']:
            # read
            r, w = o['read'], o['write']
            token = r['name']
            if r['where'] == 'body':
                if r['type'] == 'json':
                    tmp = json.loads(rs.text)
                else:
                    tmp = rs.text
            else:
                tmp = rs.headers

            data = ''
            if r['type'] == 'json':
                data = eval(f'tmp{r["getter"]}')

            # write
            if w['where'] == 'header':
                self.cred[key] = w['data']
                for k in self.cred[key]:
                    self.cred[key][k] = self.cred[key][k].replace(f'${token}$', data)
            print(self.cred)

    def _loading(self):
        # by_id
        self.doc_by_id = {}
        for hostname in self.doc['vuls']:
            vulnerability = self.doc['vuls'][hostname]
            for _id in vulnerability:
                self.doc_by_id[_id] = vulnerability[_id]
                self.doc_by_id[_id].update(dict(
                    id=_id,
                    is_vulnerable=False,
                    reason='',
                    result='NOT VULNERABLE',
                    hostname=hostname                    
                ))
        # settings
        self.settings = self.doc['settings']
        # login information
        self.login_info = [ key for key in self.doc['login'] ]

    def try_all(self):
        for hostname in self.doc['vuls']:
            for _id in self.doc['vuls'][hostname]:
                self.try_one(_id)

    def try_host(self, _hostname: str):
        for _id in self.doc['vuls'][_hostname]:
            self.try_one(_id)

    def try_one(self, _id: str):
        doc = self.doc_by_id[_id]
        dataset = dict(
            method=doc['method'].upper(),
            url=doc['url']
        )
        if 'params' in doc:
            dataset[doc['params']['type']] = doc['params']['data']

        rs = self._request(dataset)
        doc['status_code'] = rs.status_code

        for rule in doc['rules']:
            if rule == 'match':
                doc = self._match(doc, rs)

        self._reporting(doc)

    def _match(self, report, rs):
        for loc in report['rules']['match']:
            attr = report['rules']['match'][loc]
            if loc == 'header':
                self._match_header(attr, rs.headers, report)
            elif loc == 'body':
                self._match_body(attr, rs.text, report)
            else:
                pass # ERR
        return report

    def _match_header(self, l: list, headers: dict, report: dict):
        for o in l:
            name, value = o['name'], o['value']
            if name in headers and headers[name] == value:
                report['is_vulnerable'] = True
                report['reason'] = f'Found "{name}: {value}" in Header'
                report['result'] = 'VULNERABLE'
        return report['is_vulnerable']


    def _match_body(self, l: list, body: str, report: dict):
        for v in l:
            if v in body:
                report['is_vulnerable'] = True
                report['reason'] = f'Found "{v}" in Body'
                report['result'] = 'VULNERABLE'
        return report['is_vulnerable']



if __name__ == '__main__':
    w = Handler('../../tests/test.yml')
    w.try_all()
    # w.try_host('localhost2')
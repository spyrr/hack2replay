from cerberus import Validator


__all__ = [
    'validate',
    'YAML',
    'VULS',
    'ATTACK',
    'CHECK',
    'REPORT',
    'SETTINGS',
    'LOGIN'
]


def validate(doc, schema, allow_unknown=False):
    v = Validator(schema)
    v.allow_unknown=allow_unknown
    v.validate(doc)

    return v.errors


_WEB_PARAMS = dict(
    type=dict(type='string', allowed=['params', 'data', 'json']),
    data=dict(type='dict')
)


LOGIN_SUCCESS = dict(
    code=dict(type='number', required=True),
    then=dict(type='list', schema=dict(
        type='dict', schema=dict(
            read=dict(type='dict', schema=dict(
                name=dict(type='string', required=False),
                type=dict(type='string', required=False),
                where=dict(type='string', required=False),
                getter=dict(type='string', required=False)
            )),
            write=dict(type='dict', schema=dict(
                type=dict(type='string', required=False),
                where=dict(type='string', required=False),
                data=dict(type='dict', required=False)
            )),
        )
    ))
)


LOGIN = dict(
    profiles=dict(
        type='dict',
        keysrules=dict(type='string'),
        valuesrules=dict(type='dict', schema=dict(
            url=dict(type='string', required=True),
            method=dict(type='string', required=True),
            basic=dict(type='boolean', required=False),
            params=dict(type='dict', required=True, schema=_WEB_PARAMS),
            success=dict(type='dict', required=True, schema=LOGIN_SUCCESS)
        ))
    )
)


SETTINGS = dict(
    mode=dict(allowed=['dev', 'prod']),
    http=dict(type='dict', required=False, schema=dict(
        header=dict(type='dict', required=False),
        proxies=dict(type='dict', required=False, schema=dict(
            http=dict(type='string', required=False),
            https=dict(type='string', required=False),
            socks=dict(type='string', required=False)
        ))
    ))
)

#
#   Vulnerability data schema
#
REPORT = dict(
    highlight=dict(type='list', required=False, schema=dict(
        type='dict', schema=dict(
            name=dict(type='string', required=False),
            value=dict(type='string', required=False)
        )
    ))
)


CHECK = dict(
    match=dict(type='dict', required=False, schema=dict(
        header=dict(type='list', required=False, schema=dict(
            type='dict', schema=dict(
                name=dict(type='string', required=False),
                value=dict(type='string', required=False)
            )
        )),
        body=dict(type='list', required=False)
    ))
)


ATTACK = dict(
    url=dict(type='string', required=False),
    method=dict(type='string', required=False),
    header=dict(type='dict'),
    params=dict(type='dict', required=False, schema=_WEB_PARAMS),
    login=dict(type='string')
)


VULS = dict(
    id=dict(type='string'),
    host=dict(type='string'),
    service_type=dict(type='string', allowed=['web',]),
    title=dict(type='string'),
    desc=dict(type='string', required=False),
    attack=dict(type='dict', schema=ATTACK),
    check=dict(type='dict', required=False, schema=CHECK),
    report=dict(type='dict', required=False, schema=REPORT)
)


#
#   YAML document schema
#
YAML = dict(
    version=dict(type='number', allowed=[1,]),
    settings=dict(type='dict', required=False),
    login=dict(type='dict', required=False, schema=LOGIN),
    vuls=dict(type='list', schema=dict(type='dict', schema=VULS))
)

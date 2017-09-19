# -*- encoding: utf-8 -*-

import shlex

import configparser

from record import Record


def cfg_to_record(record, default_ttl, ssh_config):
    items = shlex.split(record)
    name, type, value = items[:3]
    other = items[3:]

    hostname = None
    if type == 'A':
        real_ip = ssh_config.lookup(value)['hostname']
        if real_ip != value:
            hostname = value
            value = real_ip

    ttl = default_ttl
    line = 'default'
    priority = None
    for rec in other:
        k, v = rec.split('=')
        if k == 'priority':
            priority = int(v)
        elif k == 'ttl':
            ttl = int(v)
        elif k == 'line':
            line = v

    return Record(name, type, value, ttl, line, priority=priority, hostname=hostname)


def read_config(config_path, ssh_config):
    cp = configparser.ConfigParser(delimiters=('='), inline_comment_prefixes=('#'), allow_no_value=True, strict=False)
    cp.optionxform = str
    cp.read(config_path)

    general_cfg = {k: v for (k, v) in cp.items('General')}
    general_cfg['default-ttl'] = int(general_cfg['default-ttl'])

    cp = configparser.ConfigParser(delimiters=(u'蛤'), inline_comment_prefixes=('#'), allow_no_value=True, strict=False)
    cp.optionxform = str
    cp.read(config_path)
    records = []
    for record_str in cp.items('Records'):
        record = cfg_to_record(record_str[0], general_cfg['default-ttl'], ssh_config)
        records.append(record)
    return general_cfg, records

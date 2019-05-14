# -*- coding: utf-8 -*-

import base64
import uuid
import time
import sys
import urllib
import hmac
from hashlib import sha1
from hashlib import md5
import requests
import json
from urllib import urlencode

from record import Record

def get_dns_client(client_name):
    if client_name == 'dnspod':
        return DnspodClient
    elif client_name == 'dnsimple':
        return DnsimpleClient
    elif client_name == 'aliyun':
        return AliyunClient
    elif client_name == 'cloudxns':
        return CloudxnsClient


class APIError(Exception):
    def __init__(self, msg):
        self.msg = msg
    def __str__(self):
        return repr(self.msg)


class UnsupportedLineError(Exception):
    def __init__(self, msg):
        self.msg = msg
    def __str__(self):
        return repr(self.msg)


class BaseClient(object):

    def __init__(self, api_key, api_secret):
        self.api_key = api_key
        self.api_secret = api_secret

    def list_domains(self):
        pass

    def list_records(self):
        pass

    def add_record(self):
        pass

    def remove_record(self):
        pass

    def update_record(self):
        pass


DNSPOD_LINE_MAP = {
    'default': '0',
    'ct': '10=0',
    'cu': '10=1',
    'cm': '10=3',
    'edu': '10=2',
    'oversea': '3=0',
}

DNSPOD_LINE_MAP_REV = {v: k for k, v in DNSPOD_LINE_MAP.items()}


class DnspodClient(BaseClient):
    def __init__(self, api_key, api_secret):
        super(DnspodClient, self).__init__(api_key, api_secret)
        self.base_url = 'https://dnsapi.cn/'

    def __request(self, uri, **kw):
        url = self.base_url + uri
        payload = {
            'format': 'json',
            'login_token': '%s,%s' % (self.api_key, self.api_secret),
        }
        payload.update(kw)
        r = requests.post(url, data=payload)
        r_json = r.json()

        if int(r_json['status']['code']) != 1:
            raise APIError(r_json)
        return r_json

    def __to_record(self, record):
        if record['enabled'] == '0':
            raise ValueError('Do not support DNSPod record disabled status!')

        try:
            line = DNSPOD_LINE_MAP_REV[record['line_id']]
        except KeyError:
            raise UnsupportedLineError(record)

        priority = None
        if record['type'] == 'MX':
            priority = int(record['mx'])
        if record['type'] in ('CNAME', 'MX'):
            record['value'] = record['value'].rstrip('.')

        return Record(record['name'], record['type'], record['value'], int(record['ttl']),
                   line, priority, record['id'])

    def list_records(self, domain):
        resp = self.__request('Record.List', domain=domain)
        records = []
        for r in resp['records']:
            record = self.__to_record(r)
            if record.type == 'NS':
                continue
            records.append(record)
        return records

    def add_record(self, domain, record):
        data = {
            'domain': domain,
            'sub_domain': record.name,
            'record_type': record.type,
            'value': record.value,
            'ttl': record.ttl,
        }
        data['record_line_id'] = DNSPOD_LINE_MAP[record.line]
        if type == 'MX':
            data['mx'] = record.priority
        return self.__request('Record.Create', **data)

    def remove_record(self, domain, record_id):
        return self.__request('Record.Remove', domain=domain, record_id=record_id)

    def update_record(self, domain, record_id, record):
        # Only DNSPod Enterprise can add record weight
        data = {
            'domain': domain,
            'record_id': record_id,
            'sub_domain': record.name,
            'record_type': record.type,
            'value': record.value,
            'ttl': record.ttl,
        }
        data['record_line_id'] = DNSPOD_LINE_MAP[record.line]
        if record.type == 'MX':
            data['mx'] = record.priority
        return self.__request('Record.Modify', **data)


CLOUDXNS_LINE_MAP = {
    'default': 1,
    'ct': 2,
    'cu': 3,
    'cm': 144,
    'edu': 6,
    'oversea': 9,
}

CLOUDXNS_LINE_MAP_REV = {v: k for k, v in CLOUDXNS_LINE_MAP.items()}


class CloudxnsClient(BaseClient):
    def __init__(self, api_key, api_secret):
        super(CloudxnsClient, self).__init__(api_key, api_secret)
        self.base_url = 'https://www.cloudxns.net/api2/'
        self.domain_id_map = {}

    def __request(self, method, uri, data=None):
        url = self.base_url + uri
        if data:
            data = json.dumps(data)
        else:
            data = ''
        date = time.strftime('%a %b %d %H:%M:%S %Y', time.localtime())
        md5_ins = md5()
        md5_ins.update(self.api_key + url + data + date + self.api_secret)
        headers = {
            'Content-Type': 'application/json',
            'API-FORMAT': 'json',
            'API-KEY': self.api_key,
            'API-REQUEST-DATE': date,
            'API-HMAC': md5_ins.hexdigest(),
        }
        r = requests.request(method, url, headers=headers, data=data)
        r_json = r.json()

        if int(r_json['code']) != 1:
            raise APIError(r_json)
        return r_json

    def __to_record(self, record):
        if record['status'] == 'userstop':
            raise ValueError('Do not support CloudXNS record disabled status!')
        try:
            line = CLOUDXNS_LINE_MAP_REV[int(record['line_id'])]
        except KeyError:
            raise UnsupportedLineError(record)

        priority = None
        if record['type'] == 'MX':
            priority = int(record['mx'])
        if record['type'] in ('CNAME', 'MX'):
            record['value'] = record['value'].rstrip('.')
        if record['type'] == 'TXT':
            record['value'] = record['value'].strip('"')

        return Record(record['host'], record['type'], record['value'], int(record['ttl']),
                   line, priority, record['record_id'])

    def __get_domain_id(self, domain):
        domain_id = self.domain_id_map.get(domain)
        if domain_id:
            return domain_id

        data = self.__request('GET', 'domain')
        for domain_info in data['data']:
            self.domain_id_map[domain_info['domain'].rstrip('.')] = int(domain_info['id'])
        return self.domain_id_map.get(domain)

    def list_records(self, domain):
        uri = 'record/%s' % self.__get_domain_id(domain)
        params = {
            'host_id': 0,
            'offset': 0,
            'row_num': 2000,
        }
        uri = uri + '?' + urlencode(params)
        resp = self.__request('GET', uri)
        records = []
        for r in resp['data']:
            record = self.__to_record(r)
            if record.type == 'NS':
                continue
            records.append(record)
        return records

    def add_record(self, domain, record):
        domain_id = self.__get_domain_id(domain)
        data = {
            'domain_id': domain_id,
            'host': record.name,
            'value': record.value,
            'type': record.type,
            'ttl': record.ttl,
        }
        data['line_id'] = CLOUDXNS_LINE_MAP[record.line]
        if type == 'MX':
            data['mx'] = record.priority
        return self.__request('POST', 'record', data)

    def remove_record(self, domain, record_id):
        uri = 'record/%s/%s' % (record_id, self.__get_domain_id(domain))
        return self.__request('DELETE', uri)

    def update_record(self, domain, record_id, record):
        uri = 'record/%s' % record_id
        domain_id = self.__get_domain_id(domain)
        data = {
            'domain_id': domain_id,
            'host': record.name,
            'value': record.value,
            'type': record.type,
            'ttl': record.ttl,
        }
        data['line_id'] = DNSPOD_LINE_MAP[record.line]
        if record.type == 'MX':
            data['mx'] = record.priority
        return self.__request('PUT', uri, data)

class AliyunClient(BaseClient):
    def __init__(self, api_key, api_secret):
        super(AliyunClient, self).__init__(api_key, api_secret)
        self.base_url = 'https://dns.aliyuncs.com'

    # Aliyun Signature.
    def __sign(self, params):
        sorted_parameters = sorted(params.items(),
                                   key=lambda params: params[0])
        canonicalized_query_string = ''
        for (k, v) in sorted_parameters:
            canonicalized_query_string += '&' + self.char_encode(k) + '=' + self.char_encode(v)

        string_to_sign = 'GET&%2F&' + self.char_encode(canonicalized_query_string[1:])
        h = hmac.new(str(self.api_secret) + '&', string_to_sign, sha1)
        signature = base64.encodestring(h.digest()).strip()
        return signature

    # Encode URL chars.
    def char_encode(self, encodeStr):
        encodeStr = str(encodeStr)
        res = urllib.quote(encodeStr.decode(sys.stdin.encoding).encode('utf8'), '')
        res = res.replace('+', '%20')
        res = res.replace('*', '%2A')
        res = res.replace('%7E', '~')
        return res

    def __request(self, data):
        timestamp = time.strftime('%Y-%m-%dT%H:%M:%Sz', time.gmtime())
        params = {
            'Format': 'JSON',
            'Version': '2015-01-09',
            'AccessKeyId': self.api_key,
            'SignatureVersion': '1.0',
            'SignatureMethod': 'HMAC-SHA1',
            'SignatureNonce': str(uuid.uuid1()),
            'Timestamp': timestamp
        }
        params.update(data)

        # get sign
        signature = self.__sign(params)
        params['Signature'] = signature

        r = requests.get(self.base_url, params=params)
        r_json = r.json()

        if 'Code' in r_json:
            raise APIError(r_json)
        return r_json


    def __to_record(self, record):
        if record['Status'] == 'Disable':
            raise ValueError('Do not support Aliyun DNS record disabled status!')

        try:
            line = record['Line']
        except KeyError:
            raise UnsupportedLineError(record)

        priority = None
        if record['Type'] == 'MX':
            priority = int(record['Priority'])
        if record['Type'] in ('CNAME', 'MX'):
            record['Value'] = record['Value'].rstrip('.')

        return Record(record['RR'], record['Type'], record['Value'], int(record['TTL']),
                      line, priority, record['RecordId'])

    def list_records(self, domain):
        data = {
            'Action': 'DescribeDomainRecords',
            'DomainName': domain,
            'PageSize': 500,
        }
        resp = self.__request(data)

        records = []
        for r in resp['DomainRecords']['Record']:
            record = self.__to_record(r)
            if record.type == 'NS':
                continue
            records.append(record)
        return records


    def add_record(self, domain, record):
        data = {
            'Action': 'AddDomainRecord',
            'DomainName': domain,
            'RR': record.name,
            'Type': record.type,
            'Value': record.value,
            'TTL': record.ttl,
        }
        data['Line'] = record.line
        if record.type == 'MX':
            data['Priority'] = record.priority
        return self.__request(data)

    def remove_record(self, domain, record_id):
        data = {
            'Action': 'DeleteDomainRecord',
            'RecordId': record_id,
        }
        return self.__request(data)

    def update_record(self, domain, record_id, record):
        data = {
            'Action': 'UpdateDomainRecord',
            'RecordId': record_id,
            'RR': record.name,
            'Type': record.type,
            'Value': record.value,
            'TTL': record.ttl,
        }
        data['Line'] = record.line
        if record.type == 'MX':
            data['Priority'] = record.priority
        return self.__request(data)


class DnsimpleClient(BaseClient):
    def __init__(self, api_key, api_secret):
        super(DnsimpleClient, self).__init__(api_key, api_secret)
        self.base_url = 'https://api.dnsimple.com/v2/'

    def __request(self, method, uri, data=None):
        url = self.base_url + uri
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Basic %s' % base64.b64encode(self.api_secret),
        }
        r = requests.request(method, url, headers=headers, json=data)
        if method == 'delete':
            if r.status_code != 204:
                r_json = r.json()
                raise APIError(r_json)
        else:
            r_json = r.json()
            if 'data' not in r_json:
                raise APIError(r_json)
            return r_json

    def __to_record(self, record):
        line = 'default'
        if not record['name']:
            record['name'] = '@'
        return Record(record['name'], record['type'], record['content'], int(record['ttl']),
                      line, record['priority'], record['id'])

    def list_records(self, domain):
        uri = '%s/zones/%s/records?per_page=100' % (self.api_key, domain)
        resp = self.__request('GET', uri)
        records = []
        for r in resp['data']:
            if r['system_record']:
                continue
            record = self.__to_record(r)
            if record.type == 'NS':
                continue
            records.append(record)
        return records

    def add_record(self, domain, record):
        uri = '%s/zones/%s/records' % (self.api_key, domain)
        json = {
            'name': record.name,
            'type': record.type,
            'content': record.value,
            'priority': record.priority,
            'ttl': record.ttl,
        }
        return self.__request('post', uri, json)

    def remove_record(self, domain, record_id):
        uri = '%s/zones/%s/records/%s' % (self.api_key, domain, record_id)
        return self.__request('delete', uri)

    def update_record(self, domain, record_id, record):
        uri = '%s/zones/%s/records/%s' % (self.api_key, domain, record_id)
        json = {
            'name': record.name,
            'content': record.value,
            'priority': record.priority,
            'ttl': record.ttl,
        }
        return self.__request('patch', uri, json)

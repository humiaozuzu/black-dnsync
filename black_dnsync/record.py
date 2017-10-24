# -*- coding: utf-8 -*-

import difflib

from termcolor import colored


class Record(object):
    def __init__(self, name, type, value, ttl, line=None, priority=None, record_id=None, hostname=None):
        assert isinstance(ttl, int), 'ttl should be an interger type!'
        assert isinstance(priority, int) or (priority == None)
        self.name = name
        self.type = type
        self.value = value
        self.ttl = ttl
        self.line = line
        self.priority = priority # only avaliable for MX records
        self.record_id = record_id # only available for record init from cloud
        self.hostname = hostname

    def __str__(self):
        return unicode(self).encode('utf-8')

    def __unicode__(self):
        record_items = self.to_list(show_hostname=True)
        return ' '.join(record_items)

    def __eq__(self, other):
        return all([
            self.name == other.name,
            self.type == other.type,
            self.value == other.value,
            self.ttl == other.ttl,
            self.line == other.line,
            self.priority == other.priority,
        ])

    def __ne__(self, other):
        return not self.__eq__(other)

    def delta(self, other):
        cnt = 0
        if self.value != other.value:
            cnt += 1
        if self.ttl != other.ttl:
            cnt += 1
        if self.line != other.line:
            cnt += 1
        if self.priority != other.priority:
            cnt += 1
        return cnt

    def get_close_matches(self, records):
        for record in records:
            delta = self.delta(record)
            if delta == 1:
                return record

    def to_list(self, show_hostname=False):
        items = [self.name, self.type, self.value, 'ttl=%s' % self.ttl]

        if self.type == 'TXT':
            items[2] = wrap_txt(items[2])
        if self.line and self.line != 'default':
            items.append('line=%s' % self.line)
        if self.type == 'MX':
            items.append('priority=%s' % self.priority)
        if show_hostname and self.hostname:
            items[2] =  items[2] + '(%s)' % self.hostname
        return items

    def to_cfg(self):
        """api, MX, 11.11.11.11, ttl=600, priority=20, line=edu"""
        return ' '.join(self.to_list())


def wrap_txt(value):
    return '"%s"' % value


def unwrap_txt(value):
    return value[1:-1]


def build_records_map(records):
    records_map = {}
    for record in records:
        key = (record.type, record.name)
        records_map.setdefault(key, [])
        records_map[key].append(record)
    return records_map


def diff_record_update(old, new):
    d = difflib.Differ()
    result = d.compare(old.to_list(show_hostname=True), new.to_list(show_hostname=True))
    old_list = []
    new_list = []
    for line in result:
        if line.startswith('  '):
            old_list.append(colored(line[2:], 'red'))
            new_list.append(colored(line[2:], 'green'))
        elif line.startswith('- '):
            old_list.append(colored(line[2:], 'red', attrs=['reverse']))
        elif line.startswith('+ '):
            new_list.append(colored(line[2:], 'green', attrs=['reverse']))
    return ' '.join(old_list), ' '.join(new_list)


def diff_records(old, new):
    # remove union records
    for old_record in old[:]:
        if old_record in new:
            old.remove(old_record)
            new.remove(old_record)

    add = []
    update = []
    remove = []

    old_map = build_records_map(old)
    new_map = build_records_map(new)

    for key, new_content_list in new_map.iteritems():
        if key not in old_map:
            add.extend(new_content_list)
        else:
            old_content_list = old_map[key]
            # find bi-least_delta matches
            for old_record in old_content_list:
                matched_update = old_record.get_close_matches(new_content_list)
                if matched_update is None:
                    remove.append(old_record)
                else:
                    update.append((old_record, matched_update))
                    new_content_list.remove(matched_update)
            # left update records must be add
            for new_record in new_content_list:
                add.append(new_record)

    for key, old_content_list in old_map.iteritems():
        if key not in new_map:
            remove.extend(old_content_list)

    return add, update, remove

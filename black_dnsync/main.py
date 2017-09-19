# -*- encoding: utf-8 -*-

import getopt
import sys
import os

import paramiko
from termcolor import colored, cprint

from record import Record
from record import diff_records
from record import diff_record_update
from dns_client import get_dns_client
from config import read_config

def main():
    shortopts = 'hc:'
    longopts = ['export', 'sync', 'quite', 'dry-run', 'domain=', 'provider=', 'app-id=', 'app-key=']
    optlist, args = getopt.getopt(sys.argv[1:], shortopts, longopts)

    run_sync = False
    run_export = False
    config_path = None
    dry_run = False
    quite = False
    domain = None
    provider = None
    app_id = None
    app_key = None
    for o, a in optlist:
        if o in ('-h', '--help'):
            print 'Usage: blackdnsync --sync -c path_to_config.conf [--quite] [--dry-run]'
            print '       blackdnsync --export --domain domain --provider dnspod --app-id id --app-key key'
            sys.exit(0)
        elif o in ('--sync'):
            run_sync = True
        elif o in ('--export'):
            run_export = True
        elif o in ('-c', '--config'):
            config_path = a
        elif o in ('--quite'):
            quite = True
        elif o in ('--dry-run'):
            dry_run = True
        elif o in ('--domain'):
            domain = a
        elif o in ('--provider'):
            provider = a
        elif o in ('--app-id'):
            app_id = a
        elif o in ('--app-key'):
            app_key = a

    if run_export:
        dns_client = get_dns_client(provider)
        client = dns_client(app_id, app_key)
        records = client.list_records(domain)
        for record in records:
            print record.to_cfg()
    elif run_sync:
        # load .ssh/config for later host lookup
        client = paramiko.SSHClient()
        ssh_config = paramiko.SSHConfig()
        user_config_file = os.path.expanduser("~/.ssh/config")
        if os.path.exists(user_config_file):
            with open(user_config_file) as f:
                ssh_config.parse(f)

        # get local config and records
        cfg, local_records = read_config(config_path, ssh_config)

        # pull latest records
        dns_client = get_dns_client(cfg['provider'])
        client = dns_client(cfg['app-id'], cfg['app-key'])
        remote_records = client.list_records(cfg['domain'])

        add, update, remove = diff_records(remote_records, local_records)

        # preview changes
        print 'Records to Update:'
        for old_record, new_record in update:
            print '%s => %s' % diff_record_update(old_record, new_record)
        print '\nRecords to Remove:'
        for record in remove:
            cprint(record, 'red')
        print '\nRecords to Add:'
        for record in add:
            cprint(record, 'green')

        if all(l == [] for l in (add, update, remove)):
            print 'Nothing to change. Bye~'
            exit(0)
        # prompt to run or not
        choice = raw_input('\nSubmit changes? [Y/N]').lower()
        if choice != 'y':
            print 'Nothing to change. Bye~'
            exit(0)

        # commit changes
        for r_record, l_record in update:
            print 'Updating... %s => %s' % (r_record, l_record)
            client.update_record(cfg['domain'], r_record.record_id, l_record)
            print 'Done'
        for record in remove:
            print record
            print 'Removing... %s' % record
            client.remove_record(cfg['domain'], record.record_id)
            print 'Done'
        for record in add:
            print 'Adding... %s' % record
            client.add_record(cfg['domain'], record)
            print 'Done'


if __name__ == '__main__':
    main()

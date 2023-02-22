#!/usr/bin/env python3
import argparse
import sys
from pprint import pprint

import ipaddress
import re
import socket
import subprocess


def is_valid_fqdn(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == '.':
        hostname = hostname[:-1]
    allowed = re.compile('(?!-)[A-Z\\d-]{1,63}(?<!-)$', re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split('.'))


def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def nsupdate_cmd_add_addr(fqdn, addr, ttl):
    rev_addr = '.'.join(reversed(addr.split('.'))) + '.in-addr.arpa.'
    return '\n'.join((
            f'prereq nxdomain {fqdn}',
            f'update add {fqdn} {ttl} A {addr}',
            f'prereq nxdomain {rev_addr}',
            f'update add {rev_addr} {ttl} PTR {fqdn}',
            'send'))


def nsupdate_cmd_add_alias(fqdn, cname, ttl):
    return '\n'.join((
            f'prereq nxdomain {fqdn}',
            f'update add {fqdn} {ttl} CNAME {cname}',
            'send'))


def nsupdate_cmd_add_round_robin(fqdn, addrs, ttl):
    return '\n'.join((
            f'prereq nxdomain {fqdn}',
            '\n'.join(f'update add {fqdn} {ttl} A {a}' for a in addrs),
            'send'))


def nsupdate_cmd_purge_fqdn(fqdn):
    cmd = (f'update delete {fqdn}',)
    ips = get_ipv4_by_hostname(fqdn)
    if len(ips) == 1:
        addr = ips[0]
        rev_addr = '.'.join(reversed(addr.split('.'))) + '.in-addr.arpa.'
        cmd += (f'update delete {rev_addr}',)
    return '\n'.join(cmd + ('send',))


def get_ipv4_by_hostname(hostname):
    try:
        return list(i[4][0] for i in socket.getaddrinfo(hostname, 0)
                                if i[0] is socket.AddressFamily.AF_INET
                                    and i[1] is socket.SocketKind.SOCK_RAW)
    except socket.gaierror:
        return list()


def main():
    parser = argparse.ArgumentParser(
        description='A convenience wrapper around nsupdate(1).',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog='Supported command syntax:\n'
        '* Create A and PTR records:\t%(prog)s add FQDN IP\n'
        '* Create CNAME record:\t\t%(prog)s add FQDN-1 FQDN-2\n'
        '* Create round-robin A records:\t%(prog)s add FQDN IP-1 IP-2 ...\n'
        '* Delete A, PTR, CNAME records:\t%(prog)s purge FQDN\n')
    parser.add_argument('action', choices=('add', 'purge'),
        help='action to execute')
    parser.add_argument('cmd', metavar='ARG', nargs='+', 
        help='FQDN or IP address (see examples at the bottom)')
    parser.add_argument('--key', metavar='PATH', required=True,
        help='TSIG key file for nsupdate')
    parser.add_argument('--server',
        help='DSN server address (default: use local-host mode)')
    parser.add_argument('--ttl', metavar='SECONDS', type=int, default=3600, 
        help='time to live (default: 3600)')
    parser.add_argument('--dry-run', action='store_true', 
        help='print out nsupdate commands and exit')

    args = parser.parse_args()
    pprint(args)

    fqdn = args.cmd[0]
    vals = args.cmd[1:]
    if not is_valid_fqdn(fqdn):
        parser.error(f'Failed to parse command: "{fqdn}" is not a valid FQDN.')
    fqdn = (fqdn if fqdn.endswith('.') else fqdn + '.')

    if args.action == 'add':
        if len(vals) == 0:
            parser.error('Failed to parse command: incomplete command.')
        elif len(vals) == 1:
            if is_valid_ip(vals[0]):
                nsupdate_cmd = nsupdate_cmd_add_addr(fqdn, vals[0], args.ttl)
            elif is_valid_fqdn(vals[0]):
                nsupdate_cmd = nsupdate_cmd_add_alias(fqdn, vals[0], args.ttl)
            else:
                parser.error('Failed to parse command: second ARG not as expected.')
        elif len(vals) > 1:
            if all(is_valid_ip(v) for v in vals):
                nsupdate_cmd = nsupdate_cmd_add_round_robin(fqdn, vals, args.ttl)
            else:
                parser.error('Failed to parse command: expected valid IP addresses.')
    if args.action == 'purge':
        if len(args.cmd) != 1:
            parser.error('Failed to parse command.')
        nsupdate_cmd = nsupdate_cmd_purge_fqdn(fqdn)

    if args.dry_run:
        print(nsupdate_cmd)
    else:
        subprocess.run(['cat'], input=bytes(nsupdate_cmd, encoding='ascii'))
        

if __name__ == '__main__':
    sys.exit(main())


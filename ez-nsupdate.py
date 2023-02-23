#!/usr/bin/env python3
"""Convenience wrapper for nsupdate(1)

This script is intended to simplify common DNS manipulations by generating a list
of nsupdate(1) commands and either executing or printing them.

The main value-adds are (1) automatic creation of PTR records when an A record is
created, and (2) some sanity checking.

See --help output for details.
"""
import argparse
import sys

import ipaddress
import re
import socket
import subprocess

def validate_fqdn(hostname):
    orig_hostname = hostname
    if len(hostname) > 255:
        raise ValueError
    if hostname[-1] == '.':
        hostname = hostname[:-1]
    allowed = re.compile('(?!-)[A-Z\\d-]{1,63}(?<!-)$', re.IGNORECASE)
    if all(allowed.match(x) for x in hostname.split('.')):
        return orig_hostname
    else:
        raise ValueError


def validate_ip(ip):
    ipaddress.ip_address(ip)
    # if ip is invalid ValueError will be raised, which is what we want for argparse
    return ip


def nsupdate_add_addr(fqdn, addr, ttl):
    rev_addr = '.'.join(reversed(addr.split('.'))) + '.in-addr.arpa.'
    return '\n'.join((
            f'prereq nxdomain {fqdn}',
            f'update add {fqdn} {ttl} A {addr}',
            'send',
            f'prereq nxdomain {rev_addr}',
            f'update add {rev_addr} {ttl} PTR {fqdn}',
            'send'))


def nsupdate_add_alias(fqdn, cname, ttl):
    return '\n'.join((
            f'prereq nxdomain {fqdn}',
            f'update add {fqdn} {ttl} CNAME {cname}',
            'send'))


def nsupdate_add_round_robin(fqdn, addrs, ttl):
    return '\n'.join((
            f'prereq nxdomain {fqdn}',
            '\n'.join(f'update add {fqdn} {ttl} A {a}\nsend' for a in addrs)))


def nsupdate_purge_fqdn(fqdn):
    cmd = (f'update delete {fqdn}', 'send')
    ips = get_ipv4_by_hostname(fqdn)
    if len(ips) == 1:
        addr = ips[0]
        rev_addr = '.'.join(reversed(addr.split('.')))
        cmd += (f'update delete {rev_addr}.in-addr.arpa.', 'send')
    return '\n'.join(cmd)


def get_ipv4_by_hostname(hostname):
    try:
        return list(i[4][0] for i in socket.getaddrinfo(hostname, 0)
                                if i[0] is socket.AddressFamily.AF_INET
                                    and i[1] is socket.SocketKind.SOCK_RAW)
    except socket.gaierror:
        return list()


def main():
    parser = argparse.ArgumentParser(
        description='A convenience wrapper around nsupdate(1).')
    parser.add_argument('--noop', action='store_true', 
        help='print out nsupdate command list and exit')
    parser.add_argument('--key', metavar='PATH', required=True,
        help='TSIG key file for nsupdate')
    parser.add_argument('--server', metavar='ADDRESS',
        help='DSN server address (default: use local-host mode)')
    parser.add_argument('--ttl', metavar='SECONDS', type=int, default=3600, 
        help='time to live (default: 3600)')
    parser.add_argument('--name', metavar='FQDN', required=True, type=validate_fqdn,
        help='host name to act on')

    group = parser.add_argument_group('actions')
    mxgroup = group.add_mutually_exclusive_group()
    mxgroup.add_argument('--add-addr', metavar='IP',
        help='create A and PTR records for FQDN')
    mxgroup.add_argument('--add-rr', metavar='IP', nargs='+', type=validate_ip,
        help='create A record round-robin for FQDN')
    mxgroup.add_argument('--add-alias', metavar='FQDN-2', type=validate_fqdn,
        help='create CNAME mapping FQDN to FQDN-2')
    mxgroup.add_argument('--purge', action='store_true',
        help='delete A, PTR or CNAME records of FQDN')

    args = parser.parse_args()
    print(args)

    if not args.name.endswith('.'):
        args.name += '.'

    if args.add_addr:
        nsupdate_script = nsupdate_add_addr(args.name, args.add_addr, args.ttl)
    elif args.add_alias:
        nsupdate_script = nsupdate_add_alias(args.name, args.add_alias, args.ttl)
    elif args.add_rr:
        nsupdate_script = nsupdate_add_round_robin(args.name, args.add_rr, args.ttl)
    elif args.purge:
        nsupdate_script = nsupdate_purge_fqdn(args.name)

    nsupdate_cmd = ['nsupdate', '-k', args.key]
    if args.server:
        nsupdate_script = f'server {args.server}\n' + nsupdate_script
    else:
        nsupdate_cmd.append('-l')
    if args.noop:
        print(nsupdate_cmd)
        print(nsupdate_script)
    else:
        subprocess.run(nsupdate_cmd, input=bytes(nsupdate_script, encoding='ascii'))
       

if __name__ == '__main__':
    sys.exit(main())


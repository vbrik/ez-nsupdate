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


def nsupdate_add_addr(fqdn, addr, ttl):
    """
    Generate list of nsupdate scripts that create A and PTR resource records.

    The generated scripts will not overwrite existing resource records.

    Args:
        fqdn (str): name of the A resource record
        addr (str): IP address to map hostname to
        ttl (int): time to live
    Returns:
        list: list nsupdate scripts
    """
    rev_addr = '.'.join(reversed(addr.split('.')))
    return ['\n'.join([f'prereq nxdomain {fqdn}',
                        f'update add {fqdn} {ttl} A {addr}',
                        'send']),
            '\n'.join([f'prereq nxdomain {rev_addr}.in-addr.arpa.',
                        f'update add {rev_addr}.in-addr.arpa. {ttl} PTR {fqdn}',
                        'send'])]


def nsupdate_add_alias(fqdn, cname, ttl):
    """
    Generate nsupdate script that creates CNAME resource records.

    The generated script will not overwrite existing resource records.

    Args:
        fqdn (str): name of the resource record
        cname (str): cname value
        ttl (int): time to live
    Returns:
        list: nsupdate script as a string inside a list
    """
    return ['\n'.join((
            f'prereq nxdomain {fqdn}',
            f'update add {fqdn} {ttl} CNAME {cname}',
            'send'))]


def nsupdate_add_round_robin(fqdn, addrs, ttl):
    """
    Generate nsupdate script that creates A record round-robin.

    The generated script will not overwrite existing resource records.

    Args:
        fqdn (str): name of the resource record
        addrs (list): list of IP addresses
        ttl (int): time to live
    Returns:
        list: list of nsupdate scripts
    """
    cmds = [f'update add {fqdn} {ttl} A {a}' + '\n' + 'send' for a in addrs]
    cmds[0] = f'prereq nxdomain {fqdn}' + '\n' + cmds[0]
    return cmds


def nsupdate_purge_fqdn(fqdn):
    """
    Generate nsupdate script that deletes A, PTR, or CNAME records of fqdn.

    Args:
        fqdn (str): name of the resource record
        addrs (list): list of IP addresses
        ttl (int): time to live
    Returns:
        list: list of nsupdate scripts
    """
    cmd = [f'update delete {fqdn}' + '\n' + 'send']
    ips = get_ipv4_by_hostname(fqdn)
    # Only delete PTR records if fqdn resolves to a single address. If fqdn
    # is a round-robin we don't want to delete PTRs.
    if len(ips) == 1:
        addr = ips[0]
        rev_addr = '.'.join(reversed(addr.split('.')))
        cmd += [f'update delete {rev_addr}.in-addr.arpa.' + '\n' + 'send']
    return cmd


def get_ipv4_by_hostname(hostname):
    """
    Resolve hostname.

    Args:
        hostname (str): hostname to resolve
    Returns:
        list: list of IP addresses
    """
    try:
        # https://docs.python.org/3/library/socket.html#socket.getaddrinfo
        return list(i[4][0] for i in socket.getaddrinfo(hostname, 0)
                                if i[0] is socket.AddressFamily.AF_INET
                                    and i[1] is socket.SocketKind.SOCK_RAW)
    except socket.gaierror:
        return list()


def validate_fqdn(hostname):
    """
    Check that hostname is a valid DNS name.

    Args:
        hostname (str): hostname to validate
    Returns:
        str: hostname if it is valid
    Raises:
        ValueError: if hostname is not valid
    """
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
    """
    Check that ip is a valid IP address

    Args:
        ip (str): ip to validate
    Returns:
        str: IP if it is valid
    Raises:
        ValueError: if IP is not valid
    """
    ipaddress.ip_address(ip)
    # if ip is invalid ValueError will be raised, which is what we want for argparse
    return ip


def main():
    parser = argparse.ArgumentParser(
        description='A convenience wrapperaround nsupdate(1).')
    parser.add_argument('--noop', action='store_true', 
        help='print out nsupdate command list and exit')
    parser.add_argument('--key', metavar='PATH', required=True,
        help='TSIG key file for nsupdate')
    parser.add_argument('--server', metavar='ADDRESS',
        help='DSN server address (default: use local-host mode)')
    parser.add_argument('--ttl', metavar='SECONDS', type=int, default=3600, 
        help='time to live (default: 3600)')
    parser.add_argument('--name', metavar='FQDN', required=True, type=validate_fqdn,
        help='resource record name')

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

    if not args.name.endswith('.'):
        args.name += '.'

    if args.add_addr:
        nsupdate_scripts = nsupdate_add_addr(args.name, args.add_addr, args.ttl)
    elif args.add_alias:
        nsupdate_scripts = nsupdate_add_alias(args.name, args.add_alias, args.ttl)
    elif args.add_rr:
        nsupdate_scripts = nsupdate_add_round_robin(args.name, args.add_rr, args.ttl)
    elif args.purge:
        nsupdate_scripts = nsupdate_purge_fqdn(args.name)

    nsupdate_cmd = ['nsupdate', '-k', args.key]
    if args.server:
        for i in range(len(nsupdate_scripts)):
            nsupdate_scripts[i] = f'server {args.server}\n' + nsupdate_scripts[i]
    else:
        nsupdate_cmd.append('-l')

    print('Commands sent to nsupdate:')
    for script in nsupdate_scripts:
        print(script)
        if not args.noop:
            subprocess.run(nsupdate_cmd, input=bytes(script, encoding='ascii'), check=True)


if __name__ == '__main__':
    sys.exit(main())

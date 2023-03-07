#!/usr/bin/env python3
"""Convenience wrapper for nsupdate(1)

This script is intended to simplify common DNS manipulations by generating a
list of nsupdate(1) commands and either executing or just printing them out.

The main value-adds are (1) automatic creation and cleanup of PTR records
together with A records, and (2) fewer typos.

See --help output for details.
"""
import argparse
import subprocess
import sys


def nsupdate_add_addr(fqdn, addr, ttl):
    """
    Generate a list of two nsupdate scripts that create A and PTR resource
    records if no record with the same name of any type exists.
    """
    rev_addr = '.'.join(reversed(addr.split('.')))
    add_a = '\n'.join([f'prereq nxdomain {fqdn}',
                        f'update add {fqdn} {ttl} A {addr}',
                        'send'])
    add_ptr = '\n'.join([f'prereq nxdomain {rev_addr}.in-addr.arpa.',
                        f'update add {rev_addr}.in-addr.arpa. {ttl} PTR {fqdn}',
                        'send'])
    return [add_a, add_ptr]


def nsupdate_add_alias(fqdn, cname, ttl):
    """
    Generate nsupdate script that creates a CNAME resource record if no record
    with the same name of any type exists.
    """
    return ['\n'.join((
            f'prereq nxdomain {fqdn}',
            f'update add {fqdn} {ttl} CNAME {cname}',
            'send'))]


def nsupdate_add_round_robin(fqdn, addrs, ttl):
    """
    Generate a list of nsupdate scripts that create A record round-robin if
    no record with the same name of any time exists.
    """
    cmds = [f'update add {fqdn} {ttl} A {a}' + '\n' + 'send' for a in addrs]
    cmds[0] = f'prereq nxdomain {fqdn}' + '\n' + cmds[0]
    return cmds


def nsupdate_purge_fqdn(fqdn):
    """
    Generate nsupdate script that deletes A, PTR, or CNAME records of fqdn,
    depending on what kind of record fqdn is.
    """
    import socket
    hostname, aliases, addrs = socket.gethostbyname_ex(fqdn)

    if aliases:
        # This FQDN is an alias. Just delete it.
        return [f'update delete {fqdn} CNAME' + '\n' + 'send']
    elif len(addrs) > 1:
        # This FQDN is an A record round-robin. Delete all.
        return [f'update delete {fqdn} A' + '\n' + 'send']
    elif len(addrs) == 1:
        # This FQDN is a unique A record. Delete it and the PTR pointing to this FQDN.
        rev_addr = '.'.join(reversed(addrs[0].split('.')))
        return [f'update delete {fqdn} A' + '\n' + 'send',
                f'prereq yxdomain {rev_addr}.in-addr.arpa.' + '\n'
                    + f'update delete {rev_addr}.in-addr.arpa. PTR {fqdn}'
                    + '\n' + 'send']


def validate_fqdn(hostname):
    """
    Check that hostname is a valid DNS name.

    Args:
        hostname (str): hostname to validate
    Returns:
        str: hostname if it is valid, possibly with trailing dot appended
    Raises:
        ValueError: if hostname is not valid
    """
    import re
    if len(hostname) > 255:
        raise ValueError
    if hostname[-1] == '.':
        hostname = hostname[:-1]
    allowed = re.compile('(?!-)[A-Z\\d-]{1,63}(?<!-)$', re.IGNORECASE)
    if all(allowed.match(x) for x in hostname.split('.')):
        return hostname + '.'
    else:
        raise ValueError


def validate_ip(ipaddr):
    """
    Check that ipaddr is a valid IP address

    Args:
        ipaddr (str): IP to validate
    Returns:
        str: unchanged ipaddr if IP is a valid IP address
    Raises:
        ValueError: if ipaddr is not a valid IP address
    """
    import ipaddress
    # if ip is invalid ValueError will be raised, which is what we want for argparse
    ipaddress.ip_address(ipaddr)
    return ipaddr


def main():
    parser = argparse.ArgumentParser(
        description='A convenience wrapper for nsupdate(1) in local-host mode.',
        epilog='Notes: (1) --purge on a unique (non-round-robin) A record will '
        'also delete the corresponding PTR record if that PTR points back to '
        'the FQDN being purged. '
        '(2) this script cannot delete broken CNAMEs.')
    parser.add_argument('--noop', action='store_true', 
        help='print out nsupdate command list and exit')
    parser.add_argument('--key', metavar='PATH', required=True,
        help='TSIG key file to pass to nsupdate')
    parser.add_argument('--name', metavar='FQDN', required=True, type=validate_fqdn,
        help='resource record name')
    parser.add_argument('--ttl', metavar='SECONDS', type=int, default=3600, 
        help='time to live (default: 3600)')

    group = parser.add_argument_group('actions')
    mxgroup = group.add_mutually_exclusive_group()
    mxgroup.add_argument('--add-addr', metavar='IP',
        help='create A and PTR records for FQDN')
    mxgroup.add_argument('--add-rr', metavar='IP', nargs='+', type=validate_ip,
        help='create A record round-robin for FQDN')
    mxgroup.add_argument('--add-alias', metavar='TGT-FQDN', type=validate_fqdn,
        help='create CNAME mapping FQDN to TGT-FQDN')
    mxgroup.add_argument('--purge', action='store_true',
        help='delete CNAME, or A and possibly PTR records of FQDN (see notes)')
    
    args = parser.parse_args()

    if args.add_addr:
        nsupdate_scripts = nsupdate_add_addr(args.name, args.add_addr, args.ttl)
    elif args.add_alias:
        nsupdate_scripts = nsupdate_add_alias(args.name, args.add_alias, args.ttl)
    elif args.add_rr:
        nsupdate_scripts = nsupdate_add_round_robin(args.name, args.add_rr, args.ttl)
    elif args.purge:
        nsupdate_scripts = nsupdate_purge_fqdn(args.name)

    nsupdate_cmd = ['nsupdate', '-l', '-k', args.key]
    print('nsupdate command:', ' '.join(nsupdate_cmd))

    print('nsupdate input:')
    for script in nsupdate_scripts:
        print('\033[7m' + script, end='\033[0m\n')
        if not args.noop:
            try:
                subprocess.run(nsupdate_cmd, 
                               input=bytes(script, encoding='ascii'), check=True)
            except subprocess.CalledProcessError as e:
                print('Error: nsupdate failed with return code', e.returncode)
                sys.exit(e.returncode)


if __name__ == '__main__':
    sys.exit(main())

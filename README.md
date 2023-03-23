# ez-nsupdate

ez-nsupdate.py is a convenience wrapper for nsupdate(1)
This script is intended to simplify common DNS manipulations by generating a
list of nsupdate(1) commands and either executing or just printing them out.
The main value-adds are (1) automatic creation and cleanup of PTR records
together with A records, and (2) fewer typos.

```
usage: ez-nsupdate.py [-h] [--noop] [--ttl SECONDS] --name FQDN [--add-addr IP | --add-rr IP [IP ...] | --add-alias TGT-FQDN | --purge]

A convenience wrapper for nsupdate(1) in local-host mode.

options:
  -h, --help            show this help message and exit
  --noop                print out nsupdate command list and exit
  --ttl SECONDS         time to live (default: 3600)
  --name FQDN           resource record name

action arguments:
  --add-addr IP         create A and PTR records for FQDN
  --add-rr IP [IP ...]  create A record round-robin for FQDN
  --add-alias TGT-FQDN  create CNAME mapping FQDN to TGT-FQDN
  --purge               delete CNAME, or A and possibly PTR records of FQDN (see notes)

Notes: (1) --purge on a unique (non-round-robin) A record will also delete the corresponding PTR record if that PTR points back to the FQDN being
purged.
```

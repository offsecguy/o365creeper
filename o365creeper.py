#!/usr/bin/python

# Created by Korey McKinley, Senior Security Consulant at LMG Security
# https://lmgsecurity.com
# July 12, 2019

# Updated by offsecguy for Python2/3 and request throttling support.

# This tool will query the Microsoft Office 365 web server to determine
# if an email account is valid or not. It does not need a password and
# should not show up in the logs of a client's O365 tenant.

# Note: Microsoft has implemented some throttling on this service, so
# quick, repeated attempts to validate the same username over and over
# may produce false positives. This tool is best ran after you've gathered
# as many email addresses as possible through OSINT in a list with the
# -f argument.

from __future__ import print_function
import requests as req
import argparse
import re
import sys
import time

url = 'https://login.microsoftonline.com/common/GetCredentialType'

def validate_email(email, output_file=None, throttle=0.5):
    body = '{"Username":"%s"}' % email
    response = req.post(url, data=body).text

    valid = re.search('"IfExistsResult":0', response)
    invalid = re.search('"IfExistsResult":1', response)

    if invalid:
        print('%s - INVALID' % email)
    elif valid:
        print('%s - VALID' % email)
        if output_file:
            with open(output_file, 'a') as file:
                file.write(email + '\n')
    else:
        print('%s - UNKNOWN' % email)

    time.sleep(throttle)

def main():
    parser = argparse.ArgumentParser(
        description='Enumerates valid email addresses from Office 365 without submitting login attempts.',
        epilog='Examples:\n  o365creeper.py -e test@example.com\n  o365creeper.py -f emails.txt\n  o365creeper.py -f emails.txt -o validemails.txt\n  o365creeper.py -f emails.txt -o validemails.txt -t 5',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-e', '--email', help='Single email address to validate.')
    parser.add_argument('-f', '--file', help='File containing a list of email addresses to validate, one per line.')
    parser.add_argument('-o', '--output', help='File to save valid email addresses.')
    parser.add_argument('-t', '--throttle', type=float, default=0.5, help='Throttle time in seconds between requests (default: 0.5).')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if args.file:
        try:
            with open(args.file, 'r') as file:
                for line in file:
                    email = line.strip()
                    validate_email(email, args.output, args.throttle)
        except IOError:
            print("Error: File '%s' not found." % args.file)
            sys.exit(1)
    elif args.email:
        validate_email(args.email, args.output, args.throttle)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()


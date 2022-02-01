import argparse
import datetime
import ipaddress
import re
import sys

class GrepCIDR:
    """Search lines for IP addresses within CIDRs"""

    _rx_IPv4 = r'(?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?'

    def __init__(self, haystacks, f, e, o, h, p):

        self._haystacks = [haystacks] if isinstance(haystacks, str) else haystacks
        self._needles   = []
        self._o = o
        self._p = p

        self._format = '{2}'
        if p:
            self._format = '{1}:{2}'
        if not h:
            self._format = f"{{0}}:{self._format}"

        self.add_needles_from_files(f)
        self.add_needles_from_str(e)
        
        self.rx_IPv4 = re.compile(GrepCIDR._rx_IPv4)

    def add_needles_from_files(self, needles):

        if not needles:
            return

        needles = [needles] if isinstance(needles, str) else needles

        for needle in needles:
            with open(needle, 'r') as f:
                for line in f:
                    self._needles.append(ipaddress.ip_network(line.rstrip()))

    def add_needles_from_str(self, needles):

        if not needles:
            return

        needles = [needles] if isinstance(needles, str) else needles

        [self._needles.append(ipaddress.ip_network(needle)) for needle in needles]

    def search(self):

        for haystack in self._haystacks:
            with open(haystack, 'r') as f:
                for line in f:
                    for match in self.rx_IPv4.finditer(line):
                        for net in self._needles:
                            if ipaddress.ip_address(match[0]) in net:
                                print(self._format.format(haystack, net, match[0] if self._o else line.rstrip()))


if __name__ == '__main__':

    argp = argparse.ArgumentParser()
    argp.add_argument('file', nargs='+', help='file to search')
    argp.add_argument('-f', action='append',
            help='read CIDRs from this file')
    argp.add_argument('-e', action='append', help='CIDRs')
    argp.add_argument('-p', action='store_true', help='Include pattern that matched in the output.')
    argp.add_argument('-o', action='store_true',
            help='output the matching IP address only, not the whole line')
    argp.add_argument('--no-file', action='store_true',
            help='don\'t output matching file name')
    args = argp.parse_args()

    if not args.f and not args.e:
        sys.stderr.write('Error: CIDR not provided\n')
        sys.exit(1)

    grepcidr = GrepCIDR(args.file, args.f, args.e, args.o, args.no_file, args.p)
    grepcidr.search()

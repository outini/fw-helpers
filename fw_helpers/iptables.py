#
#    Python firewall helpers (fw-helpers)
#
#    Copyright (C) 2017 Denis Pompilio (jawa) <denis.pompilio@gmail.com>
#
#    This file is part of fw-helpers
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of the GNU General Public License
#    as published by the Free Software Foundation; either version 2
#    of the License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, see <http://www.gnu.org/licenses/>.

"""Iptables parsing and simulation support for Python
"""

import logging
# module ipaddress is python3 base
from ipaddress import ip_interface as cidr
from collections import OrderedDict


DISCARD_CHAINS = ['REJECT', 'DROP']
END_CHAINS = ['ACCEPT', 'REDIRECT', 'DNAT', 'SNAT'] + DISCARD_CHAINS
RETURN_CHAINS = ['RETURN', 'LOG']
# ANY_CIDR = ipaddress.ip_interface('0.0.0.0/0')

_logger = logging.getLogger(__name__)


class Rule(dict):
    """Firewall rule object

    :param int fline: Rule number in firewall dump
    :param str table: Netfilter table name (raw, nat, filter, etc.)
    :param str rule_line: Iptables line to parse
    """

    def __init__(self, fline, table, rule_line):
        super(Rule, self).__init__()
        self._str = rule_line

        fields = self._str.split()
        self._args = dict(zip(fields[0::2], fields[1::2]))

        # Todo: improve iptables format parsing
        # WARN: Be careful with no arg or multiple args options.
        #   -4, -6, !
        #   -f, --fragment
        #   -c, --set-counters packets bytes
        #   --tcp-flags

        self._fline = fline  # [internal] line in parsed file
        self._table = table  # [internal] iptables table

        # Register parsed options
        self.i_opt("chain", '-A')
        self.i_opt("in_nic", '--in-interface', '-i', d='any')
        self.i_opt("out_nic", '--out-interface', '-o', d='any')
        self.i_opt("sip", '--source', '-s', d='0.0.0.0/0')
        self.i_opt("dip", '--destination', '-d', d='0.0.0.0/0')
        self.i_opt("module", '-m', '--match')
        self.i_opt("proto", '--protocol', '-p', d='any')
        self.i_opt("icmp_type", '--icmp-type')
        self.i_opt("spt", '--sport', d='any')
        self.i_opt("dpt", '--dport', d='any')
        self.i_opt("flow_desc", '--comment')
        self.i_opt("state", '--state')
        self.i_opt("goto", '--goto', '-g')
        self.i_opt("jump", '--jump', '-j')

        if self['jump'] == 'SNAT':
            self.i_opt("snat", '--to-source', '--to')
        elif self['jump'] == 'DNAT':
            self.i_opt("dnat", '--to-destination', '--to')

    def __repr__(self):
        """Rule representation
        """
        line_format = ("{!s:>6} "            # line from parsed file
                       "{!s:>8}/{!s:25}  "   # table and chain
                       "{!s:>15}:{!s:<5} "   # source ip and port
                       "=|{!s:10}|=> "       # protocol representation
                       "{!s:>18}:{!s:<5}  "  # destination ip and port
                       "{!s:>15}: {!s}"      # action
                       )

        if self['jump'] == 'DNAT':
            action = "destination-nat"
            action_info = self['dnat']
        elif self['jump'] == 'SNAT':
            action = "source-nat"
            action_info = self['snat']
        elif self['jump'] in DISCARD_CHAINS:
            action = "cnx-discarded"
            action_info = self['jump']
        elif self['jump'] in END_CHAINS:
            action = "table-end"
            action_info = self['jump']
        else:
            action = "jump-to"
            action_info = self['jump']

        return line_format.format(
                str(self._fline),
                str(self._table), str(self['chain']),
                str(self['sip']), str(self.get('spt')),
                str(self['proto']),
                str(self['dip']), str(self.get('dpt')),
                action, action_info)

    def __eq__(self, other):
        """Rule equality check
        """
        if not isinstance(other, self.__class__):
            return NotImplemented
        return (self['sip'] == other['sip'] and
                self['spt'] == other['spt'] and
                self['proto'] == other['proto'] and
                self['dip'] == other['dip'] and
                self['dpt'] == other['dpt'] and
                self['jump'] == other['jump'])

    def i_opt(self, key, *opts, d=None):
        """Load iptables option, with default value fallback

        :param str key: Dictionary key to use to store the value
        :param str opts: Iptables line fields to match on
        :param obj d: Default value to use if field is not found
        :return: :obj:`None`
        """
        for opt in opts:
            if opt in self._args:
                self[key] = self._args[opt]
                return
        self[key] = d

    def match(self, cnx_data):
        """Match connection data against rule data

        :param dict cnx_data: Connection data
        :return: :class:`tuple` of match result and connection data
                 (:class:`bool`, :class:`dict`)
        """
        if self['state'] and cnx_data['state'] not in self['state'].split(','):
            return False, cnx_data
        if self['proto'] != 'any' and cnx_data['proto'] != self['proto']:
            return False, cnx_data
        if cnx_data['src'].ip not in cidr(self['sip']).network:
            return False, cnx_data
        if self['spt'] != 'any' and cnx_data['spt'] != self['spt']:
            return False, cnx_data
        if cnx_data['dst'].ip not in cidr(self['dip']).network:
            return False, cnx_data
        if self['dpt'] != 'any' and cnx_data['dpt'] != self['dpt']:
            return False, cnx_data

        if self._table == "nat":
            if self.get('snat'):
                try:
                    nat_ip, nat_port = self['snat'].split(':')
                    cnx_data['src'] = cidr(nat_ip)
                    cnx_data['spt'] = nat_port
                except ValueError:
                    cnx_data['src'] = cidr(self['snat'])
            if self.get('dnat'):
                try:
                    nat_ip, nat_port = self['dnat'].split(':')
                    cnx_data['dst'] = cidr(nat_ip)
                    cnx_data['dpt'] = nat_port
                except ValueError:
                    cnx_data['dst'] = cidr(self['dnat'])

        return True, cnx_data


class IptablesFirewall(object):
    """Firewall class based on iptables

    :param str live_firewall_file: Firewall dump file path
    """

    def __init__(self, live_firewall_file=None):
        """Initialization method
        """
        self.live_firewall_file = live_firewall_file
        self._flatrules = None
        self.tables = OrderedDict()

        self.colors = {'blue': '\033[94m',
                       'yellow': '\033[93m',
                       'red': '\033[91m'}

        if self.live_firewall_file:
            _logger.debug('Parsing firewall')
            with open(self.live_firewall_file) as fwfd:
                lines = self.parse_firewall(fwfd.readlines())
            _logger.debug('Firewall parsed: %d lines' % (lines,))

    def parse_firewall(self, firewall_rows):
        """Parse firewall extract
        """
        fline = 0
        table = None
        table_name = None
        for row in firewall_rows:
            fline += 1
            if row.startswith('*'):
                table_name = row[1:].strip()
                self.tables[table_name] = OrderedDict()
                table = self.tables[table_name]

            if not row.startswith('-A'):
                continue

            rule = Rule(fline, table_name, row)

            if rule['chain'] not in table:
                table[rule['chain']] = []
            table[rule['chain']].append(rule)
        return fline

    @property
    def flatrules(self):
        """Flatten iptables multi-chain rules

        This method tries to aggregate multiple chain matching into a single
        iptables rule. It return a simplify and (much) lighter version of the
        provided firewall dump.

        :return: Flattened rules set (:class:`list` of :class:`.Rule`)
        """
        def rundown(fw_table, chain):
            flatrules = []
            for rule in fw_table.get(chain, []):
                # Ignore state based rules
                if rule['state'] and 'NEW' not in rule['state'].split(','):
                    continue

                if rule['jump'] in END_CHAINS + RETURN_CHAINS:
                    if rule not in flatrules:
                        flatrules.append(rule)
                    continue

                for frule in rundown(fw_table, rule['jump']):
                    if frule['jump'] not in END_CHAINS + RETURN_CHAINS:
                        continue

                    if frule['sip'] == '0.0.0.0/0':
                        frule['sip'] = rule['sip']
                    if frule['spt'] == 'any':
                        frule['spt'] = rule['spt']
                    if frule['proto'] == 'any':
                        frule['proto'] = rule['proto']
                    if frule['dip'] == '0.0.0.0/0':
                        frule['dip'] = rule['dip']
                    if frule['dpt'] == 'any':
                        frule['dpt'] = rule['dpt']

                    # frule._fline = rule._fline
                    frule['chain'] = rule['chain']

                    if frule not in flatrules:
                        flatrules.append(frule)

            return flatrules

        if not self._flatrules:
            table = self.tables['filter']
            self._flatrules = rundown(table, 'FORWARD')

        return self._flatrules

    # TODO: implement start at table functionality with default table="raw"
    def trace_cnx(self, cnx_data):
        """Trace a connection through the live firewall

        :param dict cnx_data: Connection data
        :return: Matched rules (:class:`list` of :class:`.Rule`)
        """
        # if table not in self.tables:
        #     raise ValueError('Unknown table: %s' % (table,))

        tables_order = [
            ('raw', 'PREROUTING'),
            ('mangle', 'PREROUTING'),
            ('nat', 'PREROUTING'),
            ('mangle', 'FORWARD'),
            ('filter', 'FORWARD'),
            ('mangle', 'POSTROUTING'),
            ('nat', 'POSTROUTING')
        ]

        matched_rules = []
        for name, chain in tables_order:
            matches = self.run_chain(name, chain, cnx_data)
            if matches:
                matched_rules.extend(matches)

                # stop processing if cnx has been discarded
                if matches[-1]['jump'] in DISCARD_CHAINS:
                    break

        return matched_rules

    def run_chain(self, table_name, chain, cnx_data):
        """Run a connection against chain's rules

        :param str table_name: Netfilter table name (raw, nat, filter, etc.)
        :param chain: Table's chain (INPUT, FORWARD, OUTPUT, etc.)
        :param cnx_data: Connection data
        :return: Matched rules (:class:`list` of :class:`.Rule`)
        """
        table = self.tables.get(table_name)

        if not table:
            return []

        if chain in END_CHAINS + RETURN_CHAINS:
            return []

        if chain not in table:
            return []

        matches = []
        for rule in table[chain]:
            (match, cnx_data) = rule.match(cnx_data)
            if not match:
                continue

            matches.append(rule)
            submatches = self.run_chain(table_name, rule['jump'], cnx_data)
            if submatches:
                matches.extend(submatches)

            if matches[-1]['jump'] in END_CHAINS:
                return matches

        return matches


if __name__ == "__main__":
    pass

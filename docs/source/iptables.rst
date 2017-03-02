fw_helpers.iptables -- Iptables parsing in Python
=================================================

    .. autoclass:: fw_helpers.iptables.Rule

        .. automethod:: fw_helpers.iptables.Rule.i_opt
        .. automethod:: fw_helpers.iptables.Rule.match

    .. autoclass:: fw_helpers.iptables.IptablesFirewall

        .. autoattribute:: fw_helpers.iptables.IptablesFirewall.flatrules
        .. automethod:: fw_helpers.iptables.IptablesFirewall.parse_firewall
        .. automethod:: fw_helpers.iptables.IptablesFirewall.trace_cnx
        .. automethod:: fw_helpers.iptables.IptablesFirewall.run_chain
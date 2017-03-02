iptables-tracer - Troubleshoot your Iptables rules
==================================================

DESCRIPTION
***********

iptables-tracer is a simple script to simulate the processing of a connection
through Netfilter. It parses the output of iptables-save command to load
Netfilter's rules and simulate those.

SYNOPSIS
********

    ``iptables-tracer FW_FILE -p PROTO -s SRC -d DST [--state STATE]``

OPTIONS
*******

::

    FW_FILE         Firewall file produced by `iptables-save`
    -p PROTO        Connection protocol
    -s SRC          Connection source  SRC_IP[:SRC_PORT]
    -d DST          Connection destination  DST_IP[:DST_PORT]
    --state STATE   Connexion state [default: NEW]

EXAMPLE
*******

    ``iptables-tracer fw.dump -p tcp -s 1.2.3.4 -d 2.3.4.5:22 --state NEW``
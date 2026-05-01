#!/usr/bin/env python
"""
Mininet topology for the Botnet DDoS lab.

Implements the design specified in ``docs/topology.md``:

  * 6 ISPs (A-F), each a /24 LAN behind an edge router and an L2 switch.
  * 45 bots + 37 normal hosts, distributed unevenly per ``ISP_PROFILES``.
  * A core router (R-core) that interconnects every edge router over
    point-to-point /30 links carved out of 172.16.0.0/16.
  * A datacenter segment (10.0.100.0/24) hosting the victim target,
    two decoys, and a monitor.
  * A hidden C2 segment (10.0.200.0/24) reachable only from bot IP
    ranges, enforced by an iptables ACL on the C2 edge router.
  * Static routes on every router (no dynamic routing protocol).

Running (inside the Mininet VM, as root):

    sudo python3 topology/topo.py

The script drops into the Mininet CLI once the network is up so that
``pingall``, ``xterm``, ``tcpdump`` on monitor / R-dc / R-c2, and
botnet / attack scripts can be launched interactively.
"""

from __future__ import annotations

import argparse
from ipaddress import ip_network

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import Node, OVSBridge
from mininet.topo import Topo

# ---------------------------------------------------------------------------
# Configuration table -- docs/topology.md 
# Editing this table reshapes the experiment; wiring and addressing are
# derived from it.
# ---------------------------------------------------------------------------
ISP_PROFILES = [
    # name,    subnet,         character,           bots, normal
    ("ISP-A", "10.0.1.0/24", "Residential",          14,  6),
    ("ISP-B", "10.0.2.0/24", "Small Business",        2, 11),
    ("ISP-C", "10.0.3.0/24", "University",            9,  4),
    ("ISP-D", "10.0.4.0/24", "Mobile",                5,  8),
    ("ISP-E", "10.0.5.0/24", "IoT / Cloud",          15,  2),
    ("ISP-F", "10.0.6.0/24", "Clean Enterprise",      0,  6),
]

DC_SUBNET  = "10.0.100.0/24"
DC_GATEWAY = "10.0.100.1"
C2_SUBNET  = "10.0.200.0/24"
C2_GATEWAY = "10.0.200.1"

BOT_SLOT_START    = 21   # bot IPs start at .21
NORMAL_SLOT_START = 51   # normal-host IPs start at .51

CORE_LINK_SUPERNET = "172.16.0.0/16"  # /30 carved per uplink


def core_link(index: int):
    """Return (core_side_cidr, edge_side_cidr) for uplink *index* (1-based).

    Each /30 is 172.16.<index>.0/30 with .1 on the core side and .2 on
    the edge side.
    """
    return f"172.16.{index}.1/30", f"172.16.{index}.2/30"


# ---------------------------------------------------------------------------
# Router node
# ---------------------------------------------------------------------------
class LinuxRouter(Node):
    """A Mininet host that forwards IPv4 and acts as an L3 router."""

    def config(self, **params):
        super().config(**params)
        self.cmd("sysctl -w net.ipv4.ip_forward=1")
        # Disable reverse-path filter; with multiple interfaces and the
        # asymmetric route knowledge described in §6 it causes legitimate
        # packets to be dropped.
        self.cmd("sysctl -w net.ipv4.conf.all.rp_filter=0")
        self.cmd("sysctl -w net.ipv4.conf.default.rp_filter=0")

    def terminate(self):
        self.cmd("sysctl -w net.ipv4.ip_forward=0")
        super().terminate()


# ---------------------------------------------------------------------------
# Topology builder
# ---------------------------------------------------------------------------
class BotnetTopo(Topo):
    """Project topology -- see ``docs/topology.md`` for the narrative spec."""

    def build(self):
        # -- Core router ------------------------------------------------
        rcore = self.addHost("Rcore", cls=LinuxRouter, ip=None)

        # -- ISP LANs ---------------------------------------------------
        for idx, (name, cidr, _character, n_bots, n_normal) in enumerate(
            ISP_PROFILES, start=1
        ):
            letter = name[-1]                         # A, B, ... F
            subnet = ip_network(cidr)
            gw_ip  = str(subnet.network_address + 1)  # .1 is the gateway

            edge = self.addHost(f"R{idx}", cls=LinuxRouter, ip=None)
            sw   = self.addSwitch(f"s{idx}")

            # LAN link: router side holds the gateway IP.
            self.addLink(
                sw, edge,
                intfName2=f"R{idx}-eth0",
                params2={"ip": f"{gw_ip}/24"},
            )

            # Uplink to core router (point-to-point /30).
            core_side, edge_side = core_link(idx)
            self.addLink(
                edge, rcore,
                intfName1=f"R{idx}-eth1",
                params1={"ip": edge_side},
                intfName2=f"Rcore-eth{idx}",
                params2={"ip": core_side},
            )

            # Bots: IPs .21 .. .20+n
            for b in range(1, n_bots + 1):
                host_ip = str(subnet.network_address + BOT_SLOT_START + b - 1)
                h = self.addHost(
                    f"bot{letter}{b}",
                    ip=f"{host_ip}/24",
                    defaultRoute=f"via {gw_ip}",
                )
                self.addLink(h, sw)

            # Normal hosts: IPs .51 .. .50+m
            for n in range(1, n_normal + 1):
                host_ip = str(subnet.network_address + NORMAL_SLOT_START + n - 1)
                h = self.addHost(
                    f"normal{letter}{n}",
                    ip=f"{host_ip}/24",
                    defaultRoute=f"via {gw_ip}",
                )
                self.addLink(h, sw)

        # -- Datacenter -------------------------------------------------
        rdc = self.addHost("Rdc", cls=LinuxRouter, ip=None)
        # Explicit DPID: name is non-canonical (no trailing digits), so
        # Mininet cannot derive one automatically.
        sdc = self.addSwitch("sdc", dpid="0000000000000007")
        self.addLink(
            sdc, rdc,
            intfName2="Rdc-eth0",
            params2={"ip": f"{DC_GATEWAY}/24"},
        )

        dc_idx = len(ISP_PROFILES) + 1
        core_side, edge_side = core_link(dc_idx)
        self.addLink(
            rdc, rcore,
            intfName1="Rdc-eth1",
            params1={"ip": edge_side},
            intfName2=f"Rcore-eth{dc_idx}",
            params2={"ip": core_side},
        )

        for hname, ip in (
            ("target",   "10.0.100.10/24"),
            ("webdecoy", "10.0.100.11/24"),
            ("dnsdecoy", "10.0.100.12/24"),
            ("monitor",  "10.0.100.200/24"),
        ):
            h = self.addHost(hname, ip=ip, defaultRoute=f"via {DC_GATEWAY}")
            self.addLink(h, sdc)

        # -- Hidden C2 segment -----------------------------------------
        rc2 = self.addHost("Rc2", cls=LinuxRouter, ip=None)
        sc2 = self.addSwitch("sc2", dpid="0000000000000008")
        self.addLink(
            sc2, rc2,
            intfName2="Rc2-eth0",
            params2={"ip": f"{C2_GATEWAY}/24"},
        )

        c2_idx = len(ISP_PROFILES) + 2
        core_side, edge_side = core_link(c2_idx)
        self.addLink(
            rc2, rcore,
            intfName1="Rc2-eth1",
            params1={"ip": edge_side},
            intfName2=f"Rcore-eth{c2_idx}",
            params2={"ip": core_side},
        )

        self.addLink(
            self.addHost("c2srv", ip="10.0.200.10/24",
                         defaultRoute=f"via {C2_GATEWAY}"),
            sc2,
        )


# ---------------------------------------------------------------------------
# Post start configuration: routes + ACLs
# ---------------------------------------------------------------------------
def _install_routes(net: Mininet) -> None:
    """Install static routes on every router (docs/topology.md §8)."""
    rcore = net.get("Rcore")

    # Edge routers: default via their core-side peer.
    for idx in range(1, len(ISP_PROFILES) + 1):
        core_ip = f"172.16.{idx}.1"
        r = net.get(f"R{idx}")
        r.cmd(f"ip route add default via {core_ip}")

    # Datacenter + C2 edge routers.
    dc_idx = len(ISP_PROFILES) + 1
    c2_idx = len(ISP_PROFILES) + 2
    net.get("Rdc").cmd(f"ip route add default via 172.16.{dc_idx}.1")
    net.get("Rc2").cmd(f"ip route add default via 172.16.{c2_idx}.1")

    # Core router: explicit /24 routes per leaf subnet via its edge.
    for idx, (_name, cidr, *_rest) in enumerate(ISP_PROFILES, start=1):
        rcore.cmd(f"ip route add {cidr} via 172.16.{idx}.2")

    rcore.cmd(f"ip route add {DC_SUBNET} via 172.16.{dc_idx}.2")
    rcore.cmd(f"ip route add {C2_SUBNET} via 172.16.{c2_idx}.2")


def _install_c2_acl(net: Mininet) -> None:
    """Lock the C2 segment down to bot IPs only (docs/topology.md §6)."""
    rc2 = net.get("Rc2")

    # Clean slate.
    rc2.cmd("iptables -F")
    rc2.cmd("iptables -X")
    rc2.cmd("iptables -P FORWARD DROP")
    rc2.cmd("iptables -P INPUT ACCEPT")
    rc2.cmd("iptables -P OUTPUT ACCEPT")

    # Allow return traffic for any flow we already accepted.
    rc2.cmd(
        "iptables -A FORWARD -m conntrack "
        "--ctstate ESTABLISHED,RELATED -j ACCEPT"
    )

    # Permit each ISP's bot range to reach the C2 subnet, and the
    # responses back. Normal hosts, datacenter, and decoys are dropped
    # by the default policy.
    for idx, (_name, cidr, _character, n_bots, _n_normal) in enumerate(
        ISP_PROFILES, start=1
    ):
        if n_bots <= 0:
            continue
        net3 = ip_network(cidr)
        low  = str(net3.network_address + BOT_SLOT_START)
        high = str(net3.network_address + BOT_SLOT_START + n_bots - 1)
        rc2.cmd(
            f"iptables -A FORWARD -m iprange --src-range {low}-{high} "
            f"-d {C2_SUBNET} -j ACCEPT"
        )
        rc2.cmd(
            f"iptables -A FORWARD -s {C2_SUBNET} "
            f"-m iprange --dst-range {low}-{high} -j ACCEPT"
        )


def _print_summary() -> None:
    total_bots    = sum(p[3] for p in ISP_PROFILES)
    total_normals = sum(p[4] for p in ISP_PROFILES)
    info("*** Botnet DDoS lab topology\n")
    info(f"    ISPs          : {len(ISP_PROFILES)}\n")
    info(f"    Bots          : {total_bots}\n")
    info(f"    Normal hosts  : {total_normals}\n")
    info("    Datacenter    : target, webdecoy, dnsdecoy, monitor\n")
    info("    Hidden C2     : c2srv (10.0.200.10) - ACL restricted\n")
    for name, cidr, character, n_bots, n_normal in ISP_PROFILES:
        rate = (n_bots / (n_bots + n_normal)) * 100 if (n_bots + n_normal) else 0
        info(
            f"    {name:<6} {cidr:<14} {character:<18} "
            f"bots={n_bots:>2}  normal={n_normal:>2}  infected={rate:5.1f}%\n"
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def run(cli: bool = True) -> Mininet:
    topo = BotnetTopo()
    net  = Mininet(
        topo=topo,
        switch=OVSBridge,   # controller-less L2 switch
        link=TCLink,
        controller=None,
        waitConnected=False,
    )
    net.start()
    _install_routes(net)
    _install_c2_acl(net)
    _print_summary()

    if cli:
        CLI(net)
        net.stop()
    return net


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Launch the Botnet DDoS lab topology in Mininet."
    )
    parser.add_argument(
        "--no-cli",
        action="store_true",
        help="Start the network and exit without dropping into the CLI "
             "(useful for scripted runs).",
    )
    parser.add_argument(
        "--log-level",
        default="info",
        choices=["debug", "info", "output", "warning", "error", "critical"],
        help="Mininet log verbosity.",
    )
    args = parser.parse_args()

    setLogLevel(args.log_level)
    net = run(cli=not args.no_cli)
    if args.no_cli:
        net.stop()


if __name__ == "__main__":
    main()

"""Objective 3: PREOF over static routes, no FRR."""

import re

from munet.mutest.userapi import log
from munet.mutest.userapi import match_step
from munet.mutest.userapi import section
from munet.mutest.userapi import step
from munet.mutest.userapi import step_json
from munet.mutest.userapi import test_step
from munet.mutest.userapi import wait_step


def pkt_count(target, pcap, pfilter=""):
    ok, groups = match_step(
        target,
        f"tcpdump -nr {pcap} {pfilter} 2>/dev/null | wc -l",
        match=r"(\d+)",
        desc=f"{target}: count packets in {pcap} {pfilter}".rstrip(),
    )
    return int(groups[0]) if ok and groups else 0


NO_LOSS = r"\b0% packet loss"


def no_loss(output):
    return bool(re.search(NO_LOSS, output))


CAPTURES = [
    ("bridge1A", "eth1", "path1", "'udp port 6635'"),
    ("bridge2A", "eth1", "path2", "'udp port 6635'"),
    ("h2", "eth0", "listener", "'icmp or (vlan and icmp)'"),
]


def start_capture(target, iface, tag, pfilter):
    step(target, f"rm -f /tmp/obj3_{tag}.pcap /tmp/obj3_{tag}.pid")
    step(
        target,
        f"nohup tcpdump -U -Z root -ni {iface} -w /tmp/obj3_{tag}.pcap {pfilter} "
        f">/tmp/obj3_{tag}.log 2>&1 & echo $! > /tmp/obj3_{tag}.pid",
    )
    wait_step(
        target,
        f"cat /tmp/obj3_{tag}.log",
        match=f"listening on {iface}",
        desc=f"{target}: {tag} capture is live on {iface}",
        timeout=15,
    )


def stop_capture(target, tag):
    step(target, f"kill -INT $(cat /tmp/obj3_{tag}.pid)")
    wait_step(
        target,
        f"kill -0 $(cat /tmp/obj3_{tag}.pid) 2>/dev/null; echo rc=$?",
        match="rc=1",
        desc=f"{target}: {tag} capture flushed and exited",
        timeout=15,
    )


section("DNT is up on both edges, exactly once")

for edge in ("bridgeA", "bridgeB"):
    wait_step(
        edge,
        f"ps -eo comm,args | awk '$1==\"dnt\" && /{edge}.ini/' | wc -l",
        match=r"^1$",
        flags=re.MULTILINE,
        desc=f"{edge}: exactly one dnt running with {edge}.ini",
        timeout=30,
    )


section("No dynamic routing anywhere")

match_step(
    "bridgeA",
    "ps -ef | grep -E '[z]ebra|[o]spfd|[f]rr'",
    match=r"zebra|ospfd|frr",
    expect_fail=True,
    desc="No FRR daemons running in the lab",
)


section("Path-facing links are MTU 1600")

for node, iface in [
    ("bridgeA", "eth1"),
    ("bridgeA", "eth2"),
    ("bridge1A", "eth0"),
    ("bridge1A", "eth1"),
    ("bridge1B", "eth0"),
    ("bridge1B", "eth1"),
    ("bridge2A", "eth0"),
    ("bridge2A", "eth1"),
    ("bridge2B", "eth0"),
    ("bridge2B", "eth1"),
    ("bridgeB", "eth1"),
    ("bridgeB", "eth2"),
]:
    match_step(
        node,
        f"ip link show {iface}",
        match="mtu 1600",
        desc=f"{node} {iface}: MTU 1600",
    )


section("Static routes steer each tunnel endpoint onto its own path")

match_step(
    "bridgeA",
    "ip route get 10.1.3.2",
    match=r"via 10\.1\.1\.2 dev eth1",
    desc="bridgeA: bridgeB Path 1 endpoint via bridge1A on eth1",
)
match_step(
    "bridgeA",
    "ip route get 10.2.3.2",
    match=r"via 10\.2\.1\.2 dev eth2",
    desc="bridgeA: bridgeB Path 2 endpoint via bridge2A on eth2",
)
match_step(
    "bridgeB",
    "ip route get 10.1.1.1",
    match=r"via 10\.1\.3\.1 dev eth1",
    desc="bridgeB: bridgeA Path 1 endpoint via bridge1B on eth1",
)
match_step(
    "bridgeB",
    "ip route get 10.2.1.1",
    match=r"via 10\.2\.3\.1 dev eth2",
    desc="bridgeB: bridgeA Path 2 endpoint via bridge2B on eth2",
)


section("Both paths carry plain IP edge to edge")

wait_step(
    "bridgeA",
    "ping -c 2 -W 1 10.1.3.2",
    match=NO_LOSS,
    desc="bridgeA to bridgeB across Path 1",
    timeout=30,
)
wait_step(
    "bridgeA",
    "ping -c 2 -W 1 10.2.3.2",
    match=NO_LOSS,
    desc="bridgeA to bridgeB across Path 2",
    timeout=30,
)
match_step(
    "bridgeA",
    "traceroute -n -w 1 -q 1 -m 5 10.1.3.2",
    match=r"10\.1\.1\.2.*10\.1\.3\.2",
    desc="bridgeA: Path 1 traverses bridge1A then reaches bridgeB",
)
match_step(
    "bridgeA",
    "traceroute -n -w 1 -q 1 -m 5 10.2.3.2",
    match=r"10\.2\.1\.2.*10\.2\.3\.2",
    desc="bridgeA: Path 2 traverses bridge2A then reaches bridgeB",
)


section("Pin neighbours so replicated ARP stays out of the capture")

h1_mac = step_json("h1", "ip -j link show eth0")[0]["address"]
h2_mac = step_json("h2", "ip -j link show eth0")[0]["address"]
log("h1 eth0 %s, h2 eth0 %s", h1_mac, h2_mac)

step("h1", f"ip neigh replace 10.0.0.2 lladdr {h2_mac} dev eth0 nud permanent")
step("h2", f"ip neigh replace 10.0.0.1 lladdr {h1_mac} dev eth0 nud permanent")

warm = step("h1", "ping -c 2 -W 1 10.0.0.2")
test_step(no_loss(warm), "h1: warm-up ping 2/2, no loss", "h1")
test_step("DUP!" not in warm, "h1: warm-up ping has no duplicates", "h1")


section("Capture both routes and the listener, then send the burst")

for target, iface, tag, pfilter in CAPTURES:
    start_capture(target, iface, tag, pfilter)

burst = step("h1", "ping -c 10 -W 1 10.0.0.2")
log("burst output:\n%s", burst)

test_step("10 received" in burst, "h1: all 10 echo replies received", "h1")
test_step(no_loss(burst), "h1: 0% packet loss across the burst", "h1")
test_step("DUP!" not in burst, "h1: no duplicates delivered to the talker", "h1")

step("h1", "sleep 2")

for target, _, tag, _ in CAPTURES:
    stop_capture(target, tag)


section("Replication: the burst appears on both disjoint routes")

p1 = pkt_count("bridge1A", "/tmp/obj3_path1.pcap", "'dst host 10.1.3.2'")
p2 = pkt_count("bridge2A", "/tmp/obj3_path2.pcap", "'dst host 10.2.3.2'")
log("Path 1 carried %s copies, Path 2 carried %s copies", p1, p2)

test_step(p1 >= 10, f"Path 1 carried the burst ({p1} copies to 10.1.3.2)", "bridge1A")
test_step(p2 >= 10, f"Path 2 carried the burst ({p2} copies to 10.2.3.2)", "bridge2A")
test_step(
    abs(p1 - p2) <= 2,
    f"Both paths carried the same burst (Path 1 {p1}, Path 2 {p2})",
)


section("Replication carries MPLS label 100 on Path 1 and 200 on Path 2")

l100 = pkt_count(
    "bridge1A",
    "/tmp/obj3_path1.pcap",
    "'udp[8:2] = 0x0006 and udp[10] & 0xf0 = 0x40'",
)
l200 = pkt_count(
    "bridge2A",
    "/tmp/obj3_path2.pcap",
    "'udp[8:2] = 0x000c and udp[10] & 0xf0 = 0x80'",
)

test_step(l100 >= 10, f"Path 1 encapsulated with MPLS label 100 ({l100})", "bridge1A")
test_step(l200 >= 10, f"Path 2 encapsulated with MPLS label 200 ({l200})", "bridge2A")

match_step(
    "bridge1A",
    "tcpdump -nr /tmp/obj3_path1.pcap 'udp[8:2] = 0x000c' 2>/dev/null",
    match=r"IP ",
    expect_fail=True,
    desc="Path 1 carries no label 200 traffic",
)
match_step(
    "bridge2A",
    "tcpdump -nr /tmp/obj3_path2.pcap 'udp[8:2] = 0x0006' 2>/dev/null",
    match=r"IP ",
    expect_fail=True,
    desc="Path 2 carries no label 100 traffic",
)


section("Elimination: exactly one delivery per sequence at the listener")

requests = pkt_count(
    "h2",
    "/tmp/obj3_listener.pcap",
    "'icmp[icmptype] = 8 or (vlan and icmp[icmptype] = 8)'",
)
replies = pkt_count(
    "h2",
    "/tmp/obj3_listener.pcap",
    "'icmp[icmptype] = 0 or (vlan and icmp[icmptype] = 0)'",
)
log("listener saw %s requests and %s replies", requests, replies)

test_step(
    requests == 10,
    f"h2 received exactly 10 echo requests, one per sequence ({requests})",
    "h2",
)
test_step(
    replies == 10,
    f"h2 sent exactly 10 echo replies ({replies})",
    "h2",
)
test_step(
    requests < p1 + p2,
    f"{p1 + p2} copies on the wire, {requests} delivered: PEF dropped the rest",
    "h2",
)


section("Path 1 link failure, delivery continues with no reconvergence")

step("bridge1A", "ip link set eth1 down")

match_step(
    "bridgeA",
    "ping -c 2 -W 1 10.1.3.2",
    match=NO_LOSS,
    expect_fail=True,
    desc="Path 1 is broken at bridge1A",
)

failover = step("h1", "ping -c 5 -W 1 10.0.0.2")
test_step(no_loss(failover), "h1: 0% loss with Path 1 down", "h1")
test_step("DUP!" not in failover, "h1: still no duplicates with Path 1 down", "h1")

step("bridge1A", "ip link set eth1 up")
step("bridge1A", "ip route replace 10.1.3.2/32 via 10.1.2.2 dev eth1")

wait_step(
    "bridgeA",
    "ping -c 2 -W 1 10.1.3.2",
    match=NO_LOSS,
    desc="Path 1 restored after link up and static route reinstated",
    timeout=30,
)

restored = step("h1", "ping -c 5 -W 1 10.0.0.2")
test_step(no_loss(restored), "h1: 0% loss with both paths up", "h1")
test_step("DUP!" not in restored, "h1: elimination still suppressing duplicates", "h1")

#!/usr/bin/env python

#
# test_ospf_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
test_ospf_topo1.py: Test the FRR/Quagga OSPF routing daemon.
"""

import os
import re
import sys
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, '../'))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.
from mininet.topo import Topo

class OSPFTopo(Topo):
    "Test topology builder"
    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

        # Create 4 routers
        for routern in range(1, 5):
            tgen.add_router('r{}'.format(routern))

        # Create a empty network for router 1
        switch = tgen.add_switch('s1')
        switch.add_link(tgen.gears['r1'])

        # Create a empty network for router 2
        switch = tgen.add_switch('s2')
        switch.add_link(tgen.gears['r2'])

        # Interconect router 1, 2 and 3
        switch = tgen.add_switch('s3')
        switch.add_link(tgen.gears['r1'])
        switch.add_link(tgen.gears['r2'])
        switch.add_link(tgen.gears['r3'])

        # Create empty netowrk for router3
        switch = tgen.add_switch('s4')
        switch.add_link(tgen.gears['r3'])

        # Interconect router 3 and 4
        switch = tgen.add_switch('s5')
        switch.add_link(tgen.gears['r3'])
        switch.add_link(tgen.gears['r4'])

        # Create a empty network for router 4
        switch = tgen.add_switch('s6')
        switch.add_link(tgen.gears['r4'])

def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(OSPFTopo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.iteritems():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, '{}/zebra.conf'.format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF,
            os.path.join(CWD, '{}/ospfd.conf'.format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF6,
            os.path.join(CWD, '{}/ospf6d.conf'.format(rname))
        )

    # Initialize all routers.
    tgen.start_router()

def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()

# Shared test function to validate expected output.
def compare_show_ip_ospf(rname, expected):
    """
    Calls 'show ip ospf route' for router `rname` and compare the obtained
    result with the expected output.
    """
    tgen = get_topogen()
    current = tgen.gears[rname].vtysh_cmd('show ip ospf route')
    return topotest.difflines(current, expected,
                              title1="Current output",
                              title2="Expected output")

def compare_show_ipv6_ospf6(rname, expected):
    """
    Calls 'show ipv6 ospf6 route' for router `rname` and compare the obtained
    result with the expected output.
    """
    tgen = get_topogen()
    current = tgen.gears[rname].vtysh_cmd('show ipv6 ospf6 route')

    # This output has space formating and random IPv6 link addresses, we have to
    # remove them first before testing.
    current = topotest.normalize_text(current)
    expected = topotest.normalize_text(expected)

    # Remove the link addresses
    current = re.sub(r'fe80::[^ ]+', 'fe80::xxxx:xxxx:xxxx:xxxx', current)
    expected = re.sub(r'fe80::[^ ]+', 'fe80::xxxx:xxxx:xxxx:xxxx', expected)

    # Remove the time
    current = re.sub(r'\d+:\d{2}:\d{2}', '', current)
    expected = re.sub(r'\d+:\d{2}:\d{2}', '', expected)

    return topotest.difflines(current, expected,
                              title1="Current output",
                              title2="Expected output")

def test_ospf_convergence():
    "Test OSPF daemon convergence"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip('skipped because of router(s) failure')

    for rnum in range(1, 5):
        router = 'r{}'.format(rnum)

        logger.info('Waiting for router "%s" convergence', router)

        # Load expected results from the command
        reffile = os.path.join(CWD, '{}/ospfroute.txt'.format(router))
        expected = open(reffile).read()

        # Run test function until we get an result. Wait at most 60 seconds.
        test_func = partial(compare_show_ip_ospf, router, expected)
        result, diff = topotest.run_and_expect(test_func, '',
                                               count=25, wait=3)
        assert result, 'OSPF did not converge on {}:\n{}'.format(router, diff)

def test_ospf_kernel_route():
    "Test OSPF kernel route installation"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip('skipped because of router(s) failure')

    rlist = tgen.routers().values()
    for router in rlist:
        logger.info('Checking OSPF IPv4 kernel routes in "%s"', router.name)

        routes = topotest.ip4_route(router)
        expected = {
            '10.0.1.0/24': {},
            '10.0.2.0/24': {},
            '10.0.3.0/24': {},
            '10.0.10.0/24': {},
            '172.16.0.0/24': {},
            '172.16.1.0/24': {},
        }
        assertmsg = 'OSPF IPv4 route mismatch in router "{}"'.format(router.name)
        assert topotest.json_cmp(routes, expected) is None, assertmsg

def test_ospf6_convergence():
    "Test OSPF6 daemon convergence"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip('skipped because of router(s) failure')

    for rnum in range(1, 5):
        router = 'r{}'.format(rnum)

        logger.info('Waiting for router "%s" IPv6 OSPF convergence', router)

        # Load expected results from the command
        reffile = os.path.join(CWD, '{}/ospf6route.txt'.format(router))
        expected = open(reffile).read()

        # Run test function until we get an result. Wait at most 60 seconds.
        test_func = partial(compare_show_ipv6_ospf6, router, expected)
        result, diff = topotest.run_and_expect(test_func, '',
                                               count=25, wait=3)
        assert result, 'OSPF6 did not converge on {}:\n{}'.format(router, diff)

def test_ospf6_kernel_route():
    "Test OSPF kernel route installation"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip('skipped because of router(s) failure')

    rlist = tgen.routers().values()
    for router in rlist:
        logger.info('Checking OSPF IPv6 kernel routes in "%s"', router.name)

        routes = topotest.ip6_route(router)
        expected = {
            '2001:db8:1::/64': {},
            '2001:db8:2::/64': {},
            '2001:db8:3::/64': {},
            '2001:db8:100::/64': {},
            '2001:db8:200::/64': {},
            '2001:db8:300::/64': {},
        }
        assertmsg = 'OSPF IPv6 route mismatch in router "{}"'.format(router.name)
        assert topotest.json_cmp(routes, expected) is None, assertmsg

def test_ospf_json():
    "Test 'show ip ospf json' output for coherency."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip('skipped because of router(s) failure')

    for rnum in range(1, 5):
        router = tgen.gears['r{}'.format(rnum)]
        logger.info('Comparing router "%s" "show ip ospf json" output', router.name)
        expected = {
            'routerId': '10.0.255.{}'.format(rnum),
            'tosRoutesOnly': True,
            'rfc2328Conform': True,
            'spfScheduleDelayMsecs': 0,
            'holdtimeMinMsecs': 50,
            'holdtimeMaxMsecs': 5000,
            'lsaMinIntervalMsecs': 5000,
            'lsaMinArrivalMsecs': 1000,
            'writeMultiplier': 20,
            'refreshTimerMsecs': 10000,
            'asbrRouter': 'injectingExternalRoutingInformation',
            'attachedAreaCounter': 1,
            'areas': {}
        }
        # Area specific additional checks
        if router.name == 'r1' or router.name == 'r2' or router.name == 'r3':
            expected['areas']['0.0.0.0'] = {
                'areaIfActiveCounter': 2,
                'areaIfTotalCounter': 2,
                'authentication': 'authenticationNone',
                'backbone': True,
                'lsaAsbrNumber': 1,
                'lsaNetworkNumber': 1,
                'lsaNssaNumber': 0,
                'lsaNumber': 7,
                'lsaOpaqueAreaNumber': 0,
                'lsaOpaqueLinkNumber': 0,
                'lsaRouterNumber': 3,
                'lsaSummaryNumber': 2,
                'nbrFullAdjacentCounter': 2,
            }
        if router.name == 'r3' or router.name == 'r4':
            expected['areas']['0.0.0.1'] = {
                'areaIfActiveCounter': 1,
                'areaIfTotalCounter': 1,
                'authentication': 'authenticationNone',
                'lsaAsbrNumber': 2,
                'lsaNetworkNumber': 1,
                'lsaNssaNumber': 0,
                'lsaNumber': 9,
                'lsaOpaqueAreaNumber': 0,
                'lsaOpaqueLinkNumber': 0,
                'lsaRouterNumber': 2,
                'lsaSummaryNumber': 4,
                'nbrFullAdjacentCounter': 1,
            }
            # r4 has more interfaces for area 0.0.0.1
            if router.name == 'r4':
                expected['areas']['0.0.0.1'].update({
                    'areaIfActiveCounter': 2,
                    'areaIfTotalCounter': 2,
                })

        # router 3 has an additional area
        if router.name == 'r3':
            expected['attachedAreaCounter'] = 2

        output = router.vtysh_cmd('show ip ospf json', isjson=True)
        result = topotest.json_cmp(output, expected)
        assert result is None, '"{}" JSON output mismatches the expected result'.format(router.name)

def test_ospf_link_down():
    "Test OSPF convergence after a link goes down"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip('skipped because of router(s) failure')

    # Simulate a network down event on router3 switch3 interface.
    router3 = tgen.gears['r3']
    router3.peer_link_enable('r3-eth0', False)

    # Expect convergence on all routers
    for rnum in range(1, 5):
        router = 'r{}'.format(rnum)
        logger.info('Waiting for router "%s" convergence after link failure', router)
        # Load expected results from the command
        reffile = os.path.join(CWD, '{}/ospfroute_down.txt'.format(router))
        expected = open(reffile).read()

        # Run test function until we get an result. Wait at most 60 seconds.
        test_func = partial(compare_show_ip_ospf, router, expected)
        result, diff = topotest.run_and_expect(test_func, '',
                                               count=25, wait=3)
        assert result, 'OSPF did not converge on {}:\n{}'.format(router, diff)

def test_ospf_link_down_kernel_route():
    "Test OSPF kernel route installation"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip('skipped because of router(s) failure')

    rlist = tgen.routers().values()
    for router in rlist:
        logger.info('Checking OSPF IPv4 kernel routes in "%s" after link down', router.name)

        routes = topotest.ip4_route(router)
        expected = {
            '10.0.1.0/24': {},
            '10.0.2.0/24': {},
            '10.0.3.0/24': {},
            '10.0.10.0/24': {},
            '172.16.0.0/24': {},
            '172.16.1.0/24': {},
        }
        if router.name == 'r1' or router.name == 'r2':
            expected.update({
                '10.0.10.0/24': None,
                '172.16.0.0/24': None,
                '172.16.1.0/24': None,
            })
        elif router.name == 'r3' or router.name == 'r4':
            expected.update({
                '10.0.1.0/24': None,
                '10.0.2.0/24': None,
            })
        # Route '10.0.3.0' is no longer available for r4 since it is down.
        if router.name == 'r4':
            expected.update({
                '10.0.3.0/24': None,
            })
        assertmsg = 'OSPF IPv4 route mismatch in router "{}" after link down'.format(router.name)
        assert topotest.json_cmp(routes, expected) is None, assertmsg

def test_ospf6_link_down():
    "Test OSPF6 daemon convergence after link goes down"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip('skipped because of router(s) failure')

    for rnum in range(1, 5):
        router = 'r{}'.format(rnum)

        logger.info('Waiting for router "%s" IPv6 OSPF convergence after link down', router)

        # Load expected results from the command
        reffile = os.path.join(CWD, '{}/ospf6route_down.txt'.format(router))
        expected = open(reffile).read()

        # Run test function until we get an result. Wait at most 60 seconds.
        test_func = partial(compare_show_ipv6_ospf6, router, expected)
        result, diff = topotest.run_and_expect(test_func, '',
                                               count=25, wait=3)
        assert result, 'OSPF6 did not converge on {}:\n{}'.format(router, diff)

def test_ospf6_link_down_kernel_route():
    "Test OSPF kernel route installation"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip('skipped because of router(s) failure')

    rlist = tgen.routers().values()
    for router in rlist:
        logger.info('Checking OSPF IPv6 kernel routes in "%s" after link down', router.name)

        routes = topotest.ip6_route(router)
        expected = {
            '2001:db8:1::/64': {},
            '2001:db8:2::/64': {},
            '2001:db8:3::/64': {},
            '2001:db8:100::/64': {},
            '2001:db8:200::/64': {},
            '2001:db8:300::/64': {},
        }
        if router.name == 'r1' or router.name == 'r2':
            expected.update({
                '2001:db8:100::/64': None,
                '2001:db8:200::/64': None,
                '2001:db8:300::/64': None,
            })
        elif router.name == 'r3' or router.name == 'r4':
            expected.update({
                '2001:db8:1::/64': None,
                '2001:db8:2::/64': None,
            })
        # Route '2001:db8:3::/64' is no longer available for r4 since it is down.
        if router.name == 'r4':
            expected.update({
                '2001:db8:3::/64': None,
            })
        assertmsg = 'OSPF IPv6 route mismatch in router "{}" after link down'.format(router.name)
        assert topotest.json_cmp(routes, expected) is None, assertmsg

def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip('Memory leak test/report is disabled')

    tgen.report_memory_leaks()

if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
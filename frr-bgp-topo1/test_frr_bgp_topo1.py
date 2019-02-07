#!/usr/bin/env python

#
# test_fabricd_butterfly_01_numbered.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2018 by
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

import re
import sys
import pdb
import json
import pytest
import inspect
import StringIO
import ipaddress
import os, fnmatch
from time import sleep
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, '../'))
sys.path.append(os.path.join(CWD, '../lib/'))


# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from mininet.topo import Topo

# Required to instantiate the topology builder class.
from mininet.topo import Topo
from time import sleep
from lib.frr_bgp_helper import *

# Reading the data from JSON File for topology creation
jsonFile = "test_frr_bgp_topo1.json"
try:
    with open(jsonFile, 'r') as topoJson:
        topo = json.load(topoJson)
except IOError:
    print "Could not read file:", jsonFile

# Global variables
frr_cfg = {}
bgp_convergence = None
# input_dict, dictionary would be used to provide input to APIs
input_dict = {}
BGP_CONVERGENCE_TIMEOUT = 10

"""
test_frr_bgp_topo1 - Tests for BGP

Test steps
- Create topology 
  Creating 4 routers topology, r1, r2, r3 are in IBGP and r3, r4 are in EBGP
- Bring up topology 
- Verify for bgp to converge
- Create and verify static routes
- Modify/Delete and verify router-id
- Modify and verify admin distance for existing static routes
- Verify clear bgp
- Modify and verify bgp timers
- Test bgp convergence with loopback interface
- Test advertise network using network command
"""

class FoldedClosTopo(Topo):
    """
    Test topology builder
   
    * `Topo`: Topology object
    """

    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

	# Building topology from json file
 	build_topo_json(tgen, topo)

def setup_module(mod):
    """
    Sets up the pytest environment
    
    * `mod`: module name
    """

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("="*40)

    logger.info("Running setup_module to create topology")
   
    # This function initiates the topology build with Topogen...
    tgen = Topogen(FoldedClosTopo, mod.__name__)
    # ... and here it calls Mininet initialization functions.
    
    tgen.start_topology()
    
    # Uncomment following line to enable debug logs and comment - tgen.start_topology() 
    #tgen.start_topology(log_level='debug')

    router_list = tgen.routers()
    for rname, router in router_list.iteritems():
	try:
	    os.chdir(CWD)
	    os.mkdir('{}'.format(rname))
    	    os.chdir("{}/{}".format(CWD, rname))
  	    os.system('touch zebra.conf bgpd.conf')
        except IOError as (errno, strerror):
	    logger.error("I/O error({0}): {1}".format(errno, strerror))

 	router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, '{}/zebra.conf'.format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP,
            os.path.join(CWD, '{}/bgpd.conf'.format(rname))
        )

    # After loading the configurations, this function starts configured daemons.
    logger.info("Starting all routers once topology is created")
    tgen.start_router()

    logger.info("Running setup_module() done")

def teardown_module(mod):
    """
    Teardown the pytest environment
   
    * `mod`: module name
    """

    logger.info("Running teardown_module to delete topology")    
    
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()
	
    # Removing tmp files
    router_list = tgen.routers()
    for rname, router in router_list.iteritems():
	try:
            os.chdir(CWD)
            os.system("rm -rf {}".format(rname))
        except IOError as (errno, strerror):
            logger.error("I/O error({0}): {1}".format(errno, strerror))
    
    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite end time: {}".format(testsuite_run_time))
    logger.info("="*40)

def verify_rib(dut, ip_prefix, ip_mask, no_of_routes, protocol= None, next_hop = None):
    """ 
    This API is to verify RIB  BGP routes.

    * `dut`: Device Under Test, for which user wants to test the data
    * `ip_prefix`: ip address for static route
    * `no_of_routes`: number of routes to be tested
    * `protocol`[optional]: protocol name, default = None
    * `next_hop`[optional]: next_hop address, default = None
    """

    logger.info("Entering API: verify_rib()")
  	
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip('skipped because of router(s) failure')

    router_list = tgen.routers()
    for router, rnode in router_list.iteritems():
        if router != dut:
            continue

        # Verifying RIB routes
        logger.info('Checking router {} RIB:'.format(router))
	if protocol != None:
    	    command = "show ip route {} json".format(protocol)
	else:
    	    command = "show ip route json"
	    protocol = "learned"

        rib_routes_json = rnode.vtysh_cmd(command, isjson=True)
        if no_of_routes !=0:
            # Generating IPs for verification
            ip_list = generate_ips("ipv4", ip_prefix, no_of_routes)
            for st_rt in ip_list:
		st_rt = str(ipaddress.IPv4Address(st_rt)) + "/" + str(ip_mask)

                found = False
		if st_rt in rib_routes_json:
                    found = True
		    if next_hop != None:
			if rib_routes_json[st_rt][0]["nexthops"][0]["ip"] == next_hop:
                            found = True
		        else:
                            logger.error("Nexthop {} is Missing for {} route {} in RIB of router {}\n".format(next_hop, protocol, st_rt, dut))
			    return False
                if not found:
                    logger.error("Missing {} {} route in  RIB routes of router {}\n".format(st_rt, protocol, dut))
                    return False 

	    logger.info("Found all {} routes in RIB of router {}\n".format(protocol, dut))
	   
        logger.info("Exiting API: verify_rib()")

        return True

def verify_bgp_convergence():
    " This API is to verify BGP-Convergence on any router."

    logger.info("Entering API: verify_bgp_confergence()")

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip('skipped because of router(s) failure')

    for router, rnode in tgen.routers().iteritems():
        logger.info('Verifying BGP Convergence on router {}:'.format(router))
	
        for retry in range(1, 11):
            show_bgp_json = rnode.vtysh_cmd("show bgp summary json", isjson=True)
            # Verifying output dictionary show_bgp_json is empty or not
            if bool(show_bgp_json) == False:
                logger.error("BGP is not running..")
                return False

            sleeptime = 2 * retry
            if sleeptime <= BGP_CONVERGENCE_TIMEOUT:
    		# Waiting for BGP to converge
    		logger.info("Waiting for {} sec for BGP to converge on router {}...".format(sleeptime, router))
                sleep(sleeptime)
            else:
                logger.error("TIMEOUT!! BGP is not converged in {} seconds for router {}".format(BGP_CONVERGENCE_TIMEOUT, router))
		return False    

            # To find neighbor ip type
            total_peer = len(topo['routers'][router]['bgp']["bgp_neighbors"])
            no_of_peer = 0
            for bgp_neighbor, data in topo['routers'][router]['bgp']["bgp_neighbors"].iteritems():
                peer_name = topo['routers'][router]['bgp']["bgp_neighbors"][bgp_neighbor]["peer"]["name"]
                peer_label = topo['routers'][router]['bgp']["bgp_neighbors"][bgp_neighbor]["peer"]["label"]
                peer_addr_type = topo['routers'][router]['bgp']["bgp_neighbors"][bgp_neighbor]["peer"]["addr_type"]
                if "source" in topo['routers'][router]['bgp']["bgp_neighbors"][bgp_neighbor]["peer"] and \
                        topo['routers'][router]['bgp']["bgp_neighbors"][bgp_neighbor]["peer"]["source"] == 'lo':
                    # Loopback interface
                    neighbor_ip = topo['routers'][peer_name]['lo'][peer_addr_type].split("/")[0]
                    if peer_addr_type == "ipv4":
                        nh_state = show_bgp_json["ipv4Unicast"]["peers"][neighbor_ip]["state"]
                    else:
                        nh_state = show_bgp_json["ipv6Unicast"]["peers"][neighbor_ip]["state"]
    
                    if nh_state == "Established":
                        no_of_peer += 1
                else:
                    # Physical interface
                    for neighbor, data in topo['routers'][peer_name]['links'].iteritems():
                        if peer_label in data['label']:
                            neighbor_ip = topo['routers'][peer_name]['links'][neighbor][peer_addr_type].split("/")[0]
                            if peer_addr_type == "ipv4":
                                nh_state = show_bgp_json["ipv4Unicast"]["peers"][neighbor_ip]["state"]
                            else:
                                nh_state = show_bgp_json["ipv6Unicast"]["peers"][neighbor_ip]["state"]
    
                            if nh_state == "Established":
                                no_of_peer += 1
            if no_of_peer == total_peer:
                logger.info('BGP is Converged for router {}'.format(router))
                break
            else:
                logger.warning('BGP is not yet Converged for router {}'.format(router))

    logger.info("Exiting API: verify_bgp_confergence()")
    return True


#####################################################
##
##   Tests starting
##
#####################################################
def test_bgp_convergence():
    " Test BGP daemon convergence "
	
    tgen = get_topogen()
    global frr_cfg, bgp_convergence

    # test case name
    tc_name = inspect.stack()[0][3]
    logger.info("Testcase started: {} \n".format(tc_name))

    # Creating BGP configuration    
    frr_cfg = create_config_files(tgen, CWD, topo)

    # Api call verify whether BGP is converged
    bgp_convergence = verify_bgp_convergence()
        
    assert bgp_convergence, "Testcase " + tc_name + " :Failed"  
    
    logger.info("Testcase " + tc_name + " :Passed \n")
    
    # Uncomment next line for debugging
    #tgen.mininet_cli()

def test_static_routes():
    " Test to create and verify static routes. "

    tgen = get_topogen()
    global frr_cfg, bgp_convergence

    if bgp_convergence == False:
	pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    logger.info("Testcase started: {} \n".format(tc_name))

    # Creating BGP configuration    
    frr_cfg = create_config_files(tgen, CWD, topo)

    # Api call to create static routes
    input_dict = {
        "r1": {
            "static_routes":{
                     "ip_prefix": '10.0.20.1',
                     "ip_mask": 32,
                     "no_of_routes": 9,
                     "admin_distance": 100,
                     "next_hop": '10.0.0.6',
                     "tag": 4001
            },
            "redistribute": "bgp"
        }
    }
    result = create_static_routes("ipv4", input_dict, tgen, CWD, topo, frr_cfg)
        
    assert result, "Testcase " + tc_name + " :Failed"  

    # Verifying RIB routes
    dut = 'r2'
    #protocol = "bgp"
    ip_prefix = input_dict["r1"]["static_routes"]["ip_prefix"]
    ip_mask = input_dict["r1"]["static_routes"]["ip_mask"]
    no_of_routes = input_dict["r1"]["static_routes"]["no_of_routes"]
    next_hop = input_dict["r1"]["static_routes"]["next_hop"]

    # verify_rib 
    #result = verify_rib(dut, ip_prefix, ip_mask, no_of_routes, protocol = protocol, next_hop = next_hop)
    result = verify_rib(dut, ip_prefix, ip_mask, no_of_routes, next_hop = next_hop)
    
    assert result, "Testcase " + tc_name + " :Failed"  
    
    logger.info("Testcase " + tc_name + " :Passed \n")
    
    # Uncomment next line for debugging
    #tgen.mininet_cli()

if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))

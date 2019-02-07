import os
import sys
import time
import argparse
import subprocess
import json
import errno
import select
import pytest
import StringIO
import traceback
import ipaddress
import ConfigParser
from struct import pack
from struct import unpack
from socket import inet_aton
from socket import inet_ntoa
from datetime import datetime
from enum import IntEnum, Enum
from lib.topolog import logger, logger_config

if sys.version_info >= (3,):
    import io
else:
    import cStringIO

PERMIT = 1
DENY = 0
ADDR_TYPE_INVALID = 0
ADDR_TYPE_IPv4 = 1
ADDR_TYPE_IPv6 = 2
IPv4_UNICAST = 1
VPNv4_UNICAST = 2
IPv6_UNICAST = 3
number_to_router = {}
FRRCFG_FILE = 'frr.conf'
frr_cfg = {}

def get_StringIO():
    if sys.version_info >= (3,):
        return io.StringIO()
    else:
        return cStringIO.StringIO()

CD = os.path.dirname(os.path.realpath(__file__))
pytestini_path = os.path.join(CD, '../pytest.ini')

# NOTE: to save execution logs to log file frrtest_log_dir must be configured in `pytest.ini`.
config = ConfigParser.ConfigParser()
config.read(pytestini_path)

CONFIG_SECTION = 'topogen'

if config.has_option('topogen', 'verbosity'):
    loglevel = config.get('topogen', 'verbosity')
    loglevel = loglevel.upper()
else:
    loglevel = 'INFO'

if config.has_option('topogen', 'frrtest_log_dir'):
    frrtest_log_dir =  config.get('topogen', 'frrtest_log_dir')
    time_stamp = datetime.time(datetime.now())
    logfile_name = "frr_test_bgp_"
    frrtest_log_file = frrtest_log_dir + logfile_name + str(time_stamp)

    logger = logger_config.get_logger(name='test_execution_logs', log_level=loglevel, target=frrtest_log_file)
    print "Logs will be sent to logfile: {}".format(frrtest_log_file)

if config.has_option('topogen', 'show_router_config'):
    show_router_config = config.get('topogen', 'show_router_config')
else:
    show_router_config = False

###
class RoutingPB:

    def __init__(self, router_id):
        self.interfaces_cfg = None
        self.static_route = None
        self.redist_static_routes_flag = None
        self.bgp_config = None
        self.routing_global = {'router_id': router_id}
        self.community_lists = []
        self.prefix_lists = []
        self.route_maps = []


class FRRConfig:

    def __init__(self, router, routing_cfg_msg, frrcfg_file):
        self.router = router
        self.routing_pb = routing_cfg_msg
        self.errors = []
        self.interfaces_cfg = get_StringIO()
        self.routing_common = get_StringIO()
        self.static_routes = get_StringIO()
        self.as_path_prepend = False
        self.bgp_global = get_StringIO()
        self.bgp_neighbors = get_StringIO()
        self.bgp_address_family = {}
        self.bgp_address_family[IPv4_UNICAST] = get_StringIO()
        self.bgp_address_family[IPv6_UNICAST] = get_StringIO()
        self.bgp_address_family[VPNv4_UNICAST] = get_StringIO()
        self.access_lists = get_StringIO()
        self.prefix_lists = get_StringIO()
        self.route_maps = get_StringIO()
        self.community_list = get_StringIO()
        self._community_list_regex_index = 0
        self._route_map_seq_id = 0
        self.frrcfg_file = frrcfg_file

    def reset_route_map_seq_id(self):
        self._route_map_seq_id = 0

    def reset_it(self):
        self.errors = []
        self.interfaces_cfg = get_StringIO()
        self.routing_common = get_StringIO()
        self.static_routes = get_StringIO()
        self.as_path_prepend = False
        self.bgp_global = get_StringIO()
        self.bgp_neighbors = get_StringIO()
        self.bgp_address_family = {}
        self.bgp_address_family[IPv4_UNICAST] = get_StringIO()
        self.bgp_address_family[IPv6_UNICAST] = get_StringIO()
        self.bgp_address_family[VPNv4_UNICAST] = get_StringIO()
        self.access_lists = get_StringIO()
        self.prefix_lists = get_StringIO()
        self.route_maps = get_StringIO()
        self.community_list = get_StringIO()
        self._community_list_regex_index = 0
        self._route_map_seq_id = 0

    def current_route_map_seq_id(self):
        return self._route_map_seq_id

    def get_route_map_seq_id(self):
        self._route_map_seq_id = self._route_map_seq_id + 1
        return self._route_map_seq_id

    def get_community_list_regex_name(self):
        self._community_list_regex_index = self._community_list_regex_index + 1
        return 'comm-list-regex-' + str(self._community_list_regex_index)

    def print_to_file(self, topo):
        try:
            frrcfg = open(self.frrcfg_file, 'w')
        except IOError as err:
            logger.error('Unable to open FRR Config File. error(%s): %s' % (err.errno, err.strerror))
            return False

        frrcfg.write('! FRR General Config\n')
        frrcfg.write(self.routing_common.getvalue())
        frrcfg.write('! Interfaces Config\n')
        frrcfg.write(self.interfaces_cfg.getvalue())
        
	# If bgp neighborship is being done using loopback interface -
        # - then we have make the loopback interface reachability up -
        # - for that we are adding static routes -
	for router, number in number_to_router.iteritems():
            if number == self.router:
                neighbors = topo['routers']['{}'.format(router)]["bgp"]['bgp_neighbors']
                for key, value in neighbors.iteritems():
                    peer = neighbors[key]['peer']
		    ADDR_TYPE = peer['addr_type']
		    if "source" in peer and peer['source'] == 'lo':
                        add_static_route_for_loopback_interfaces(ADDR_TYPE, router, topo, frrcfg)
	
        frrcfg.write('! Static Route Config\n')
        frrcfg.write(self.static_routes.getvalue())
        frrcfg.write('! Access List Config\n')
        frrcfg.write(self.access_lists.getvalue())
        frrcfg.write('! Prefix List Config\n')
        frrcfg.write(self.prefix_lists.getvalue())
        frrcfg.write('! Route Maps Config\n')
        frrcfg.write(self.route_maps.getvalue())
        frrcfg.write('! Community List Config\n')
        frrcfg.write(self.community_list.getvalue())
        if self.is_bgp_configured:
            frrcfg.write('! BGP Config\n')
            frrcfg.write(self.bgp_global.getvalue())
            frrcfg.write(self.bgp_neighbors.getvalue())
            for addr_family in self.bgp_address_family:
                frrcfg.write('address-family ' + get_address_family(addr_family) + '\n')
                frrcfg.write(self.bgp_address_family[addr_family].getvalue())
                frrcfg.write('exit-address-family\n')

        frrcfg.write('line vty\n')
        frrcfg.close()
        return True

    def close(self):
        self.routing_common.close()
        self.static_routes.close()
        self.bgp_neighbors.close()
        self.bgp_global.close()
        for addr_family in self.bgp_address_family:
            self.bgp_address_family[addr_family].close()

        self.prefix_lists.close()
        self.route_maps.close()

    def run_shell_command(self, cmdline):
        logger.debug('executing command: %s', ' '.join(cmdline))
        try:
            output = subprocess.check_output(cmdline, stderr=subprocess.STDOUT, close_fds=True)
            logger.debug('output: %s', output)
            return True
        except subprocess.CalledProcessError as cpe:
            logger.error('Failed to execute: rc=%s, out=%s, err=%s', cpe.returncode, cpe.output, cpe)
            return False

    def _push_to_frr(self):
        cmdline = ['/usr/lib/frr/frr-reload.py',
         '--debug',
         '--test',
         FRRCFG_FILE]
        self.run_shell_command(cmdline)
        cmdline = ['/usr/lib/frr/frr-reload.py',
         '--debug',
         '--reload',
         FRRCFG_FILE]
        return self.run_shell_command(cmdline)

    def push_to_frr(self):
        for _ in range(3):
            if self._push_to_frr():
                logger.info('Successfully pushed the config to FRR')
                return True

        logger.error('Unable to push the config to FRR')
        return False

def build_topo_json(tgen, topo):
    """ 
    Builds topology from json 

    * `tgen`: Topogen object
    * `topo`: json file data
    """

    logger.info("Testing flow - Building topo####################")
    listRouters = []
    for routerN in sorted(topo['routers'].iteritems()):
        logger.info('Topo: Add router {}'.format(routerN[0]))
        tgen.add_router(routerN[0])
        listRouters.append(routerN[0])

    listRouters.sort()
    if 'ipv4base' in topo:
        ipv4Next = ipaddress.IPv4Address(topo['link_ip_start']['ipv4'])
        ipv4Step = 2 ** (32 - topo['link_ip_start']['v4mask'])
        if topo['link_ip_start']['v4mask'] < 32:
            ipv4Next += 1
    if 'ipv6base' in topo:
        ipv6Next = ipaddress.IPv6Address(topo['link_ip_start']['ipv6'])
        ipv6Step = 2 ** (128 - topo['link_ip_start']['v6mask'])
        if topo['link_ip_start']['v6mask'] < 127:
            ipv6Next += 1
    for router in listRouters:
        topo['routers'][router]['nextIfname'] = 0

    while listRouters != []:
        curRouter = listRouters.pop(0)
        for destRouter, data in sorted(topo['routers'][curRouter]['links'].iteritems()):
            if destRouter in listRouters:
                topo['routers'][curRouter]['links'][destRouter]['interface'] = '{}-{}-eth{}'.format(curRouter, destRouter, topo['routers'][curRouter]['nextIfname'])
                topo['routers'][destRouter]['links'][curRouter]['interface'] = '{}-{}-eth{}'.format(destRouter, curRouter, topo['routers'][destRouter]['nextIfname'])
                topo['routers'][curRouter]['nextIfname'] += 1
                topo['routers'][destRouter]['nextIfname'] += 1
                tgen.gears[curRouter].add_link(tgen.gears[destRouter], topo['routers'][curRouter]['links'][destRouter]['interface'], topo['routers'][destRouter]['links'][curRouter]['interface'])
                if 'ipv4' in topo['routers'][curRouter]['links'][destRouter]:
                    if topo['routers'][curRouter]['links'][destRouter]['ipv4'] == 'auto':
                        topo['routers'][curRouter]['links'][destRouter]['ipv4'] = '{}/{}'.format(ipv4Next, topo['link_ip_start']['v4mask'])
                        topo['routers'][destRouter]['links'][curRouter]['ipv4'] = '{}/{}'.format(ipv4Next + 1, topo['link_ip_start']['v4mask'])
                        ipv4Next += ipv4Step
                if 'ipv6' in topo['routers'][curRouter]['links'][destRouter]:
                    if topo['routers'][curRouter]['links'][destRouter]['ipv6'] == 'auto':
                        topo['routers'][curRouter]['links'][destRouter]['ipv6'] = '{}/{}'.format(ipv6Next, topo['link_ip_start']['v6mask'])
                        topo['routers'][destRouter]['links'][curRouter]['ipv6'] = '{}/{}'.format(ipv6Next + 1, topo['link_ip_start']['v6mask'])
                        ipv6Next = ipaddress.IPv6Address(int(ipv6Next) + ipv6Step)

        if 'lo' in topo['routers'][curRouter]:
            if topo['routers'][curRouter]['lo']['ipv4'] == 'auto':
                topo['routers'][curRouter]['lo']['ipv4'] = '{}{}.{}/{}'.format(topo['lo_prefix']['ipv4'], number_to_row(curRouter), number_to_column(curRouter), topo['lo_prefix']['v4mask'])
            if topo['routers'][curRouter]['lo']['ipv6'] == 'auto':
                topo['routers'][curRouter]['lo']['ipv6'] = '{}{}:{}/{}'.format(topo['lo_prefix']['ipv6'], number_to_row(curRouter), number_to_column(curRouter), topo['lo_prefix']['v6mask'])

def create_interfaces_cfg(curRouter, topo):
    """ Create interface configuration for created topology and
        save the configuration to frr.conf file. Basic Interface configuration
        is provided in input json file.
    
    * `curRouter` : router for which interface config should be created
    * `topo` : json file data
    """

    interfaces = Interfaces()
    if 'lo' in topo['routers'][curRouter]:
        interface_name = 'lo'
        lo_addresses = []
        if 'ipv4' in topo['routers'][curRouter]['lo']:
            lo_addresses.append(topo['routers'][curRouter]['lo']['ipv4'])
        if 'ipv6' in topo['routers'][curRouter]['lo']:
            lo_addresses.append(topo['routers'][curRouter]['lo']['ipv6'])
        interfaces.add_interface(interface_name, lo_addresses)
    for destRouter, data in sorted(topo['routers'][curRouter]['links'].iteritems()):
        interface_name = topo['routers'][curRouter]['links'][destRouter]['interface']
        int_addresses = []
        if 'ipv4' in topo['routers'][curRouter]['links'][destRouter]:
            int_addresses.append(topo['routers'][curRouter]['links'][destRouter]['ipv4'])
        if 'ipv6' in topo['routers'][curRouter]['links'][destRouter]:
            int_addresses.append(topo['routers'][curRouter]['links'][destRouter]['ipv6'])
        interfaces.add_interface(interface_name, int_addresses)

    return interfaces

def create_bgp_cfg(router, topo):
    """ 
    Create BGP configuration for created topology and
    save the configuration to frr.conf file. BGP configuration
    is provided in input json file. 
    
    * `router` : router for which bgp config should be created
    * `topo` : json file data
    """

    # Getting number for router
    i = number_to_router[router]

    # Setting key to bgp to read data from json file for bgp configuration
    key = 'bgp'
    as_number = topo['routers']['{}'.format(router)][key]['as_number']
    ecmp = topo['routers']['{}'.format(router)][key]['ecmpenabled']
    gracefull_restart = topo['routers']['{}'.format(router)][key]['gracefulrestart']
    bgp_enabled = topo['routers']['{}'.format(router)][key]['enabled']
    frr_cfg[i].is_bgp_configured = bgp_enabled
    bgp = Bgp(as_number, gracefull_restart, ecmp)

    neighbors = topo['routers']['{}'.format(router)][key]['bgp_neighbors']
    for key, value in neighbors.iteritems():
        remote_as = neighbors[key]['remoteas']
        holddowntimer = neighbors[key]['holddowntimer']
        keepalivetimer = neighbors[key]['keepalivetimer']

        # Peer details
        peer = neighbors[key]['peer']
        name = peer['name']
        label = peer['label']
        ADDR_TYPE = peer['addr_type']
        # TODO
        # Add support for multiple loopback address
        # Loopback interface
	if "source" in peer and peer['source'] == 'lo':
            ip_addr = topo['routers'][name]['lo'][ADDR_TYPE]
            ip = ip_addr.split('/')[0]
            update_source = topo['routers']['{}'.format(router)]['lo'][ADDR_TYPE].split('/')[0]
            if ADDR_TYPE == "ipv4":
                addr = Address(IPv4_UNICAST, ip, None)
                neighbor = bgp.add_neighbor(IPv4_UNICAST, addr, remote_as, keepalivetimer, holddowntimer, None, update_source, 2)
                neighbor.add_address_family(IPv4_UNICAST, True, None, None, None, None)
            else:
                addr = Address(IPv6_UNICAST, None, ip)
                neighbor = bgp.add_neighbor(IPv6_UNICAST, addr, remote_as, keepalivetimer, holddowntimer, None, update_source, 2)
                neighbor.add_address_family(IPv6_UNICAST, True, None, None, None, None)

        # Physical interface
        else:
            for linkRouter, data in sorted(topo['routers'][name]['links'].iteritems()):
                if label in data['label']:
                    ip_addr = topo['routers'][name]['links'][linkRouter][ADDR_TYPE]
                    ip = ip_addr.split('/')[0]
                    if ADDR_TYPE == "ipv4":
                	addr = Address(IPv4_UNICAST, ip, None)
                	neighbor = bgp.add_neighbor(IPv4_UNICAST, addr, remote_as, keepalivetimer, holddowntimer, None, None, 0)
                	neighbor.add_address_family(IPv4_UNICAST, True, None, None, None, None)
                    else:
                	addr = Address(IPv6_UNICAST, None, ip)
               	 	neighbor = bgp.add_neighbor(IPv6_UNICAST, addr, remote_as, keepalivetimer, holddowntimer, None, None, 0)
                	neighbor.add_address_family(IPv6_UNICAST, True, None, None, None, None)
    return bgp

def add_static_route_for_loopback_interfaces(ADDR_TYPE, router, topo, frrcfg):
    """ 
    Add static routes for loopback interfaces reachability, It will add static routes in current 
    router for other router's loopback interfaces os the reachability will be up and so will BGP neighborship. 
    
    * `ADDR_TYPE` : type of address ex - ipv4/ipv6
    * `router` : router for which static routes should be added
    * `topo` : json file data
    * `frrcfg` : frr config file to save router config
    """

    links_to_router = []
    for link, data in topo['routers'][router]['links'].iteritems():
        links_to_router.append(link)

    if ADDR_TYPE == "ipv4":
        for curRouter, data in sorted(topo['routers'].iteritems()):
            if curRouter != router:
                ip_addr = topo['routers'][curRouter]['lo']['ipv4']

                next_hop_found = False
                if curRouter in links_to_router:
                    next_hop_found = True
                    next_hop = topo['routers'][curRouter]['links'][router]['ipv4'].split("/")[0]

                destRouter = curRouter
                while not next_hop_found:
                    curRouter = destRouter
                    for destRouter, data in topo['routers'][curRouter]['links'].iteritems():
                        if destRouter in links_to_router:
                            next_hop_found = True
                            next_hop = topo['routers'][destRouter]['links'][router]['ipv4'].split("/")[0]

                frrcfg.write("ip route " + ip_addr + " " + next_hop + "\n")
    else:
        for curRouter, data in sorted(topo['routers'].iteritems()):
            if curRouter != router:
                ip_addr = topo['routers'][curRouter]['lo']['ipv6']

                next_hop_found = False
                if curRouter in links_to_router:
                    next_hop_found = True
                    next_hop = topo['routers'][curRouter]['links'][router]['ipv6'].split("/")[0]

                destRouter = curRouter
                while not next_hop_found:
                    curRouter = destRouter
                    for destRouter, data in topo['routers'][curRouter]['links'].iteritems():
                        if destRouter in links_to_router:
                            next_hop_found = True
                            next_hop = topo['routers'][destRouter]['links'][router]['ipv6'].split("/")[0]

                frrcfg.write("ipv6 route " + ip_addr + " " + next_hop + "\n")

def create_static_routes(ADDR_TYPE, input_dict, tgen, CWD, topo, frr_cfg):
    """ 
    Create  static routes for given router as defined in input_dict
    
    * `ADDR_TYPE` : type of address ex - ipv4/ipv6
    * `input_dict` : input to create static routes for given router
    * `tgen` : Topogen object
    * `CWD` : caller's current working directory
    * `topo` : json file data
    * `frrcfg` : frr config file to save router config
    """
    
    try:
        for router in input_dict.keys():
            static_routes = []
            
	    # Getting number for router
	    i = number_to_router[router]
        
            #Reset config for routers
	    frr_cfg[i].reset_it()

	    ip_prefix = input_dict[router]["static_routes"]["ip_prefix"]
	    ip_mask = input_dict[router]["static_routes"]["ip_mask"]
	    no_of_routes = input_dict[router]["static_routes"]["no_of_routes"]
	    if "admin_distance" in input_dict[router]["static_routes"]:
  	        admin_distance = input_dict[router]["static_routes"]["admin_distance"]
	    else:
		admin_distance = 1

	    if "tag" in input_dict[router]["static_routes"]:
		tag = input_dict[router]["static_routes"]["tag"]
            else:
                tag = None
	    
	    if "if_name" in input_dict[router]["static_routes"]:
		if_name = input_dict[router]["static_routes"]["if_name"]
            else:
                if_name = None

	    redistribute_to = input_dict[router]["redistribute"]
	    frr_cfg[i].routing_pb.redist_static_routes_flag = redistribute_to
	
	    ip_list = generate_ips(ADDR_TYPE, ip_prefix, no_of_routes)
	    next_hop = input_dict[router]["static_routes"]["next_hop"]
	    for ip in ip_list:
		if ADDR_TYPE == "ipv4":
	            ip = str(ipaddress.IPv4Address(ip)) + "/" + str(ip_mask)
		    addr = Address(ADDR_TYPE_IPv4, ip, None) 
		    route = Route(addr)
		    nh = Address(ADDR_TYPE_IPv4, next_hop, None)
  	   	    route.add_nexthop(nh, None, admin_distance, if_name, tag)
	  	else:
                    ip = str(ipaddress.IPv6Address(ip)) + "/" + str(ip_mask)
                    addr = Address(ADDR_TYPE_IPv6, None, ip)
                    route = Route(addr)
		    nh = Address(ADDR_TYPE_IPv4, None, next_hop)
                    route.add_nexthop(addr, None, admin_distance, if_name, tag)

                static_routes.append(route)
                frr_cfg[i].routing_pb.static_route = static_routes

            interfaces_cfg(frr_cfg[i])
            bgp_cfg(frr_cfg[i])
            static_rt_cfg(frr_cfg[i])
            redist_cfg(frr_cfg[i], topo)
            frr_cfg[i].print_to_file(topo)
	    # Load configuration to router
            load_config_to_router(tgen, CWD, router)

    except Exception as e:
        logger.error(traceback.format_exc())
        return False
    else:
        return True

def redist_cfg(frr_cfg, topo):
    """ 
    To redistribute static and connected  routes for given router. 
    
    * `topo` : json file data
    * `frrcfg` : frr config file to save router config
    """

    try:	
        if frr_cfg.is_bgp_configured:
            if frr_cfg.routing_pb.redist_static_routes_flag == 'bgp':
                for router, number in number_to_router.iteritems():
                    if number == frr_cfg.router:
                        neighbors = topo['routers']['{}'.format(router)]["bgp"]['bgp_neighbors']
                        for key, value in neighbors.iteritems():
                            peer = neighbors[key]['peer']
                            ADDR_TYPE = peer['addr_type']

            	        if ADDR_TYPE == "ipv4":
	    	            # IPv4
	    		    frr_cfg.bgp_address_family[IPv4_UNICAST].write('redistribute static\n')
            		    frr_cfg.bgp_address_family[IPv4_UNICAST].write('redistribute connected\n')
	    	        else:
		            # IPv6
            		    frr_cfg.bgp_address_family[IPv6_UNICAST].write('redistribute static\n')
            		    frr_cfg.bgp_address_family[IPv6_UNICAST].write('redistribute connected\n')
    except Exception as e:
        logger.error(traceback.format_exc())

def create_config_files(tgen, CWD, topo):
    """
    It will create BGP basic configuration(router-id only) 
    and save it to frr.conf, then it will call APIs to create
    BGP and interface configuration and all configuration would
    be saved in frr.conf file.

    * `tgen` : Topogen object
    * `CWD`  : caller's current working directory
    * `topo` : json file data 
    """
   
    try:
        listRouters = []
        for routerN in topo['routers'].iteritems():
            listRouters.append(routerN[0])
    
        listRouters.sort()
        assign_number_to_routers(listRouters)
        logger.info('Configuring nodes')
        for curRouter in number_to_router.keys():
            router = curRouter
            i = number_to_router[curRouter]
            if 'router_id' in topo['routers'][router]['bgp']:
                ip = topo['routers'][router]['bgp']['router-id']
                ip = Address(ADDR_TYPE_IPv4, ip, None)
                rid = int(socket.inet_aton(ip.ipv4).encode('hex'), 16)
                router_id = Address(ADDR_TYPE_IPv4, rid, None)
            else:
                router_id = None
            rt_cfg = RoutingPB(router_id)
            fname = '%s/r%d/frr.conf' % (CWD, i)
            frr_cfg[i] = FRRConfig(i, rt_cfg, fname)
            frr_cfg[i].is_standby = False
    
            frr_cfg[i].routing_pb.interfaces_config = create_interfaces_cfg(router, topo)
            frr_cfg[i].routing_pb.bgp_config = create_bgp_cfg(router, topo)
    
            interfaces_cfg(frr_cfg[i])
            bgp_cfg(frr_cfg[i])
            static_rt_cfg(frr_cfg[i])
            redist_cfg(frr_cfg[i], topo)
            frr_cfg[i].print_to_file(topo)
            # Load config to router
            load_config_to_router(tgen, CWD, router)

    except Exception as e:
        logger.error(traceback.format_exc())
        return False
    else:
        return frr_cfg


def load_config_to_router(tgen, CWD, routerName):
    """ 
    This API is to create a delta of running config and user defined config, upload the delta config to router. 
 
    * `tgen` : Topogen object
    * `CWD`  : caller's current working directory
    * `routerName` : router for which delta config should be generated and uploaded
    """
 
    logger.info('Entering API: load_config_to_router()')

    try:
        router_list = tgen.routers()
        for rname, router in router_list.iteritems():
            if rname == routerName:
                cfg = router.run("vtysh -c 'show running'")
                fname = '{}/{}/frr.sav'.format(CWD, rname)
                dname = '{}/{}/delta.conf'.format(CWD, rname)
                f = open(fname, 'w')
                for line in cfg.split('\n'):
                    line = line.strip()

                    if (line == 'Building configuration...' or
                       line == 'Current configuration:' or
                            not line):
                       continue
                    f.write(line)
                    f.write('\n')

                f.close()
                command = '/usr/lib/frr/frr-reload.py  --input {}/{}/frr.sav --test {}/{}/frr.conf > {}'.format(CWD, rname, CWD, rname, dname)
                result = os.system(command)

                # Assert if command fail
                if result != 0:
                    command_output = False
                    assert command_output, 'Command:{} is failed due to non-zero exit code'.format(command)

                f = open(dname, 'r')
                delta = StringIO.StringIO()
                delta.write('configure terminal\n')
                t_delta = f.read()
                for line in t_delta.split('\n'):
                    line = line.strip()
                    if (line == 'Lines To Delete' or
                        line == '===============' or
                        line == 'Lines To Add' or
                        line == '============' or
                            not line):
                        continue
                    delta.write(line)
                    delta.write('\n')

                delta.write('end\n')
                router.vtysh_multicmd(delta.getvalue())
                logger.info('New configuration for router {}:'.format(rname))
                delta.close()
                delta = StringIO.StringIO()
                cfg = router.run("vtysh -c 'show running'")
                for line in cfg.split('\n'):
                    line = line.strip()
                    delta.write(line)
                    delta.write('\n')

                # Router current  configuration to log file or console if "show_router_config" is defined in "pytest.ini"
                if show_router_config:
		    logger.info(delta.getvalue())
                delta.close()
    except Exception as e:
        logger.error(traceback.format_exc())


# Interface helper class for interface configuration
class Interface:

    def __init__(self, interface_name, interface_ip_addresses):
        self.interface_name = interface_name
        self.interface_ip_addresses = interface_ip_addresses


class Interfaces:

    def __init__(self):
        self.interfaces = []

    def add_interface(self, interface_name, interface_ip_addresses):
        for n in self.interfaces:
            if n.interface_name == interface_name:
                n.interface_ip_address.append(interface_ip_addresses)
                return

        interface = Interface(interface_name, interface_ip_addresses)
        self.interfaces.append(interface)
        return interface


def _print_interfaces_cfg(frr_cfg, interface):
    interface_name = interface.interface_name
    interface_ip_addresses = interface.interface_ip_addresses
    frr_cfg.interfaces_cfg.write('interface ' + str(interface_name) + '\n')
    for address in interface_ip_addresses:
        if '::' in address:
            frr_cfg.interfaces_cfg.write('ipv6 address ' + str(address) + '\n')
        else:
            frr_cfg.interfaces_cfg.write('ip address ' + str(address) + '\n')


def interfaces_cfg(frr_cfg):
    ifaces = frr_cfg.routing_pb.interfaces_config
    for interface in ifaces.interfaces:
        _print_interfaces_cfg(frr_cfg, interface)


# Helper class for Address family configuration
class AddressFamily:

    def __init__(self, ad_family, enabled, filter_in_prefix_list, filter_out_prefix_list, filter_in_rmap, filter_out_rmap):
        self.type = ad_family
        self.enabled = enabled
        self.filter_in_prefix_list = filter_in_prefix_list
        self.filter_out_prefix_list = filter_out_prefix_list
        self.filter_in_rmap = filter_in_rmap
        self.filter_out_rmap = filter_out_rmap

# Helper class for BGP Neighbor configuration
class Neighbor:

    def __init__(self, afi, ip_address, remote_as, keep_alive_time, hold_down_time, password, update_source, max_hop_limit = 0):
        self.afi = afi
        self.ip_address = ip_address
        self.remote_as = remote_as
        self.keep_alive_time = keep_alive_time
        self.hold_down_time = hold_down_time
        self.password = password
        self.max_hop_limit = max_hop_limit
        self.update_source = update_source
        self.address_families = []

    def add_address_family(self, ad_family, enabled, filter_in_prefix_list, filter_out_prefix_list, filter_in_rmap, filter_out_rmap):
        for f in self.address_families:
            if f.type == ad_family:
                f.enabled = enabled
                f.filter_in_prefix_list = filter_in_prefix_list
                f.filter_out_prefix_list = filter_out_prefix_list
                f.filter_in_rmap = filter_in_rmap
                f.filter_out_rmap = filter_out_rmap
                return

        family = AddressFamily(ad_family, enabled, filter_in_prefix_list, filter_out_prefix_list, filter_in_rmap, filter_out_rmap)
        self.address_families.append(family)

    def del_address_family(self, ad_family):
        for f in self.address_families:
            if f.type == ad_family:
                self.address_families.remove(f)


# Helper class for BGP configuration
class Bgp:

    def __init__(self, local_as, graceful_restart, ecmp):
        self.local_as = local_as
        self.graceful_restart = graceful_restart
        self.ecmp = ecmp
        self.neighbors = []

    def add_neighbor(self, afi, ip_address, remote_as, keep_alive_time, hold_down_time, password, update_source, max_hop_limit):
        for n in self.neighbors:
            if n.afi == afi and n.ip_address == ip_address:
                n.remote_as = remote_as
                n.keep_alive_time = keep_alive_time
                n.hold_down_time = hold_down_time
                n.password = password
                n.update_source = update_source
                n.max_hop_limit = max_hop_limit
                return

        neighbor = Neighbor(afi, ip_address, remote_as, keep_alive_time, hold_down_time, password, update_source, max_hop_limit)
        self.neighbors.append(neighbor)
        return neighbor

    def get_neighbor(self, afi, ip_address):
        for n in self.neighbors:
            if n.afi == afi and n.ip_address.ipv4 == ip_address.ipv4:
                return n

    def del_neighbor(self, afi, ip_address):
        for n in self.neighbors:
            if n.afi == afi and n.ip_address == ip_address:
                self.neighbors.remove(n)


def _print_bgp_global_cfg(frr_cfg, local_as_no, router_id, ecmp_path, gr_enable):
    frr_cfg.bgp_global.write('router bgp ' + str(local_as_no) + '\n')
    if router_id != None:
        frr_cfg.bgp_global.write('bgp router-id ' + IpAddressMsg_to_str(router_id) + ' \n')
    frr_cfg.bgp_global.write('no bgp network import-check\n')
    frr_cfg.bgp_global.write('maximum-paths ' + str(ecmp_path) + '\n')
    frr_cfg.bgp_global.write('bgp fast-external-failover\n')
    frr_cfg.bgp_global.write('bgp log-neighbor-changes\n')
    if gr_enable:
        frr_cfg.bgp_global.write(' bgp graceful-restart\n')


def _print_bgp_address_family_cfg(frr_cfg, neigh_ip, addr_family):
    out_filter_or_rmap = False
    neigh_cxt = 'neighbor ' + neigh_ip + ' '
    frr_cfg.bgp_address_family[addr_family.type].write(neigh_cxt + 'activate\n')
    if addr_family.filter_in_prefix_list != None:
        frr_cfg.bgp_address_family[addr_family.type].write(neigh_cxt + 'prefix-list ' + addr_family.filter_in_prefix_list + ' in\n')
    if addr_family.filter_out_prefix_list != None:
        frr_cfg.bgp_address_family[addr_family.type].write(neigh_cxt + 'prefix-list ' + addr_family.filter_out_prefix_list + ' out\n')
        out_filter_or_rmap = True
    if addr_family.filter_in_rmap != None:
        frr_cfg.bgp_address_family[addr_family.type].write(neigh_cxt + 'route-map ' + addr_family.filter_in_rmap + ' in\n')
    if addr_family.filter_out_rmap != None:
        frr_cfg.bgp_address_family[addr_family.type].write(neigh_cxt + 'route-map ' + addr_family.filter_out_rmap + ' out\n')
        out_filter_or_rmap = True
    if not out_filter_or_rmap and frr_cfg.as_path_prepend:
        if addr_family.type == IPv4_UNICAST:
            frr_cfg.bgp_address_family[IPv4_UNICAST].write(neigh_cxt + ' route-map ' + AS_PREPEND_RMAP_V4 + ' out\n')
        if addr_family.type == IPv6_UNICAST:
            frr_cfg.bgp_address_family[IPv6_UNICAST].write(neigh_cxt + ' route-map ' + AS_PREPEND_RMAP_V6 + ' out\n')


def _print_bgp_neighbors_cfg(frr_cfg, neighbor):
    neigh_ip = IpAddressMsg_to_str(neighbor.ip_address)
    neigh_cxt = 'neighbor ' + neigh_ip + ' '
    frr_cfg.bgp_neighbors.write(neigh_cxt + 'remote-as ' + str(neighbor.remote_as) + '\n')
    frr_cfg.bgp_neighbors.write(neigh_cxt + 'activate\n')
    frr_cfg.bgp_neighbors.write(neigh_cxt + 'disable-connected-check\n')
    if neighbor.update_source != None:
        frr_cfg.bgp_neighbors.write(neigh_cxt + 'update-source ' + neighbor.update_source + ' \n')
    keep_alive = '60'
    hold_down = '180'
    if neighbor.keep_alive_time and neighbor.hold_down_time:
        keep_alive = str(neighbor.keep_alive_time)
        hold_down = str(neighbor.hold_down_time)
    frr_cfg.bgp_neighbors.write(neigh_cxt + 'timers ' + keep_alive + ' ' + hold_down + '\n')
    if neighbor.password != None:
        frr_cfg.bgp_neighbors.write(neigh_cxt + 'password ' + neighbor.password + '\n')
    if neighbor.max_hop_limit > 1:
        frr_cfg.bgp_neighbors.write(neigh_cxt + 'ebgp-multihop ' + str(neighbor.max_hop_limit) + '\n')
        frr_cfg.bgp_neighbors.write(neigh_cxt + 'enforce-multihop\n')
    for addr_family in neighbor.address_families:
        if addr_family.type not in [IPv4_UNICAST, IPv6_UNICAST, VPNv4_UNICAST]:
            logger.error('unsupported address family')
            return False
        if addr_family.type == VPNv4_UNICAST and not addr_family.enabled:
            logger.error('vpnv4 family is not enabled')
            return False
        _print_bgp_address_family_cfg(frr_cfg, neigh_ip, addr_family)


def _print_ipv6_prefix_list(frr_cfg, name, action):
    frr_cfg.prefix_lists.write('ipv6 prefix-list ' + name + ' ' + action + '\n')


def _print_access_list(frr_cfg, name, action):
    frr_cfg.access_lists.write('access-list ' + name + ' ' + action + '\n')


def _print_as_prepand_access_list(frr_cfg):
    _print_access_list(frr_cfg, IPV4_ACCESSLIST_NUMBER_RSVD1, 'permit any')
    _print_ipv6_prefix_list(frr_cfg, IPV6_PREFIXLIST_RSVD1, 'permit  any')


def _print_as_prepand_rmap(frr_cfg, as_number, repeat = 3):
    as_prepend = (str(as_number) + ' ') * repeat
    _print_as_prepand_access_list(frr_cfg)
    frr_cfg.route_maps.write('route-map ' + AS_PREPEND_RMAP_V4 + ' permit  10\n')
    frr_cfg.route_maps.write('match ip address ' + IPV4_ACCESSLIST_NUMBER_RSVD1 + '\n')
    frr_cfg.route_maps.write('set  as-path  prepend ' + as_prepend + '\n')
    frr_cfg.route_maps.write('route-map ' + AS_PREPEND_RMAP_V6 + ' permit  10\n')
    frr_cfg.route_maps.write('set as-path  prepend ' + as_prepend + '\n')


def bgp_cfg(frr_cfg):
    if not frr_cfg.is_bgp_configured:
        logger.debug('BGP is disabled')
        return
    bgp = frr_cfg.routing_pb.bgp_config
    if bgp.ecmp:
        ecmp = 8
    else:
        ecmp = 1
    if frr_cfg.is_standby:
        frr_cfg.as_path_prepend = True
        _print_as_prepand_rmap(frr_cfg, bgp.local_as)
    _print_bgp_global_cfg(frr_cfg, bgp.local_as, frr_cfg.routing_pb.routing_global['router_id'], ecmp, bgp.graceful_restart)
    for neighbor in bgp.neighbors:
        _print_bgp_neighbors_cfg(frr_cfg, neighbor)

# Helper class for Static route nexthop configuration
class Nexthop:

    def __init__(self, ip, blackhole = False, admin_distance = 1, if_name = None, tag = None):
        self.ip = ip
        self.blackhole = blackhole
        self.admin_distance = admin_distance
        self.if_name = if_name
        self.tag = tag


# Helper class for Static route ip-prefix  configuration
class Route:

    def __init__(self, prefix):
        self.prefix = prefix
        self.nexthops = []

    def add_nexthop(self, ip, blackhole, admin_distance, if_name, tag):
        nhop = Nexthop(ip, blackhole, admin_distance, if_name, tag)
        self.nexthops.append(nhop)


def static_rt_nh(nh):
    rc = 0
    nexthop = ''
    admin_dist = '1'
    tag = None
    if nh.ip:
        nexthop = IpAddressMsg_to_str(nh.ip)
    elif nh.blackhole:
        nexthop = 'blackhole'
    if nh.if_name != None:
        nexthop = nexthop + ' ' + nh.if_name
    if nh.admin_distance > 0:
        admin_dist = str(nh.admin_distance)
    if nh.tag != None:
        tag = nh.tag
    return (rc, nexthop, admin_dist, tag)

def static_rt_cfg(frr_cfg):
    if frr_cfg.routing_pb.static_route == None:
        return
    for st in frr_cfg.routing_pb.static_route:
        prefix = IpAddressMsg_to_str(st.prefix)
        addr_type = st.prefix.afi
        ip_cmd = get_ip_cmd(addr_type)
        for nh in st.nexthops:
            rc, nexthop, admin_dist, tag = static_rt_nh(nh)
            if rc == 0:
                if tag == None:
                    frr_cfg.static_routes.write(' '.join([ip_cmd,
                     'route', prefix, nexthop, admin_dist, '\n']))
                else:
                    frr_cfg.static_routes.write(' '.join([ip_cmd,
                     'route', prefix, nexthop, 'tag', str(tag), admin_dist, '\n']))
            else:
                frr_cfg.errors.append('Static Route: ' + prefix + 'with Nexthop: ' + str(nh))

# Helper class for general Network configuration
class Network:

    def __init__(self, afi, ipv4, ipv6, prefix_length):
        self.afi = afi
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.prefix_length = prefix_length


# Helper class for Address type  configuration
class Address:

    def __init__(self, afi, ipv4, ipv6):
        self.afi = afi
        self.ipv4 = ipv4
        self.ipv6 = ipv6

####

# Common APIs written here, will be used by all other APIs
def bgp_configured(routing_cfg_msg):
    return True

def get_address_family(addr_family):
    if addr_family == IPv4_UNICAST:
        return 'ipv4 unicast'
    if addr_family == IPv6_UNICAST:
        return 'ipv6 unicast'
    if addr_family == VPNv4_UNICAST:
        return 'ipv4 vpn'
    assert 'Unknown address family'

def get_ip_cmd(addr_type):
    if addr_type == ADDR_TYPE_IPv4:
        return 'ip'
    else:
        return 'ipv6'

def IpPrefixMsg_to_str(addr, subnet = True):
    ip_string = ''
    ip_string = IpAddressMsg_to_str(addr)
    if subnet and addr.prefix_length:
        ip_string = ip_string + '/' + str(addr.prefix_length)
    return ip_string

def IpStringToInt(addr):
    return unpack('!I', inet_aton(addr))[0]

def IpAddressMsg_to_str(addr):
    if addr.afi == ADDR_TYPE_IPv4:
        return addr.ipv4
    else:
        return addr.ipv6

def int_to_aa_nn(comm):
    left_byte, right_byte = divmod(comm, 65536)
    return str(left_byte) + ':' + str(right_byte)

def number_to_row(routerName):
    """
    Returns the number for the router.
    Calculation based on name a0 = row 0, a1 = row 1, b2 = row 2, z23 = row 23 etc
    """
    return int(routerName[1:])

def number_to_column(routerName):
    """
    Returns the number for the router.
    Calculation based on name a0 = columnn 0, a1 = column 0, b2= column 1, z23 = column 26 etc
    """
    return ord(routerName[0]) - 97

def generate_ips(ADDR_TYPE, start_ip, no_of_ips):
    """
    Returns list of IPs.
    based on start_ip and no_of_ips
    
    * `ADDR_TYPE` : to identify ip address type ex- ipv4/ipv6
    * `start_ip`  : from here the ip will start generating, start_ip will be first ip
    * `no_of_ips` : these many IPs will be generated

    Limitation: It will generate IPs only for ip_mask 32
    
    """
    if ADDR_TYPE == 'ipv4':
        start_ip = ipaddress.IPv4Address(start_ip)
    else:
        start_ip = ipaddress.IPv6Address(start_ip)
    ipaddress_list = [start_ip]
    next_ip = start_ip
    count = 1
    while count <= no_of_ips:
        next_ip += 1
        ipaddress_list.append(next_ip)
        count += 1

    return ipaddress_list

def assign_number_to_routers(listRouters):
    """
    It will assign numbers to router ex- r1:1, r2:2.....r10:10
    these number would be used to save/access configuration in/from frr.conf file.
    """
    for routerNumber, routerName in enumerate(listRouters, 1):
        number_to_router[routerName] = routerNumber

####

###
# These APIs will used by testcases
def find_interface_with_greater_ip(ADDR_TYPE, topo, router):
    """  
    Returns highest interface ip for ipv4/ipv6
    
    * `ADDR_TYPE` : to identify ip address type ex- ipv4/ipv6
    * `topo`  : json file data
    * `router` : router for which hightes interface should be calculated 
    """

    if ADDR_TYPE == "ipv4":
        if 'lo' in topo['routers'][router]:
            return topo['routers'][router]['lo']['ipv4'].split('/')[0]
        interfaces_list = []
        for destRouter, data in sorted(topo['routers'][router]['links'].iteritems()):
            if 'ipv4' in topo['routers'][router]['links'][destRouter]:
                ip_address = topo['routers'][router]['links'][destRouter]['ipv4'].split('/')[0]
                interfaces_list.append(ipaddress.IPv4Address(ip_address))
    else:
        if 'lo' in topo['routers'][router]:
            ip_address = topo['routers'][router]['lo']['ipv6'].split('/')[0]
            return ipaddress.IPv4Address(ip_address)
        interfaces_list = []
        for destRouter, data in sorted(topo['routers'][router]['links'].iteritems()):
            if 'ipv6' in topo['routers'][router]['links'][destRouter]:
                ip_address = topo['routers'][router]['links'][destRouter]['ipv6'].split('/')[0]
                interfaceis_list.append(ipaddress.IPv4Address(ip_address))

    return sorted(interfaces_list)[-1]


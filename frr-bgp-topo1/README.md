### frrtopotests Overview

frrtopotests is the enhanced version of topotests. There are two main enhancements: 

1. Creating the topology and assigning IPs to router' interfaces dynamically. 
It is achieved by Using json file, in which user specify the number of routers, links to each router, interfaces for the routers and protocol configurations for all routers. 

2. Creating the configurations (interfaces, protocol) dynamically. 
It is achieved by using /usr/lib/frr/frr-reload.py utility, which takes running configuration and the newly created configuration for any particular router and creates a delta file(diff file) and loads it to  router.


### frrtopotests File Hierarchy
The file hierarchy looks like below:

```shell
$ cd path/to/frrtopotests
$ find ./*
...
./README.md  # repository read me
./conftest.py # test hooks - pytest related functions

...
./frr-bgp-topo1  # the bgp topology testsuite
./frr-bgp-topo1/test_frr_bgp_topo1.json # input json file, having topology, interfaces and bgp configuration
./frr-bgp-topo1/test_frr_bgp_topo1.py # test script to write and execute testcases
...
./lib # shared test/topology functions
./lib/frr_bgp_helper.py # library for bgp topology, configuration creation and testing 
# Other files are same as topotests
```

### Sample JSON file for Topology creation
```
JSON file:
{
"ipv4base": "10.0.0.0",
"ipv4mask": 30,
"ipv6base": "fd00::",
"ipv6mask": 64,
"link_ip_start": {"ipv4": "10.0.0.0", "v4mask": 30, "ipv6": "fd00::", "v6mask": 64},
"lo_prefix": {"ipv4": "1.0.", "v4mask": 32, "ipv6": "2001:DB8:F::", "v6mask": 128},
"routers":
    {
    "r1": {
        "lo": { "ipv4": "auto", "ipv6": "auto" },
        "links": {
                "r2": { "ipv4": "auto", "ipv6": "auto", "label": "r2-peer"},
                "r3": { "ipv4": "auto", "ipv6": "auto", "label": "r3-peer"}
                },
        "bgp": {
                "as_number": "100",
                "enabled": true,
                "ecmpenabled": true,
                "bgp_neighbors": {
                    "1": {
                        "keepalivetimer": 60,
                        "holddowntimer": 180,
                        "remoteas": "100",
                        "peer": {
                            "name": "r2",
                            "label": "r1-peer",
                            "addr_type": "ipv4",
                        }
                    },
                    "2": {
                        "keepalivetimer": 60,
                        "holddowntimer": 180,
                        "remoteas": "100",
                        "peer": {
                            "name": "r3",
                            "label": "r1-peer",
                            "addr_type": "ipv4",
                        }
                    }
                },
                "gracefulrestart":true
               }
    },
    "r2": {
        "lo": { "ipv4": "auto", "ipv6": "auto"},
        "links": {
                "r1": { "ipv4": "auto", "ipv6": "auto", "label": "r1-peer"},
                "r3": { "ipv4": "auto", "ipv6": "auto", "label": "r3-peer"}
                },
        "bgp": {
                "as_number": "100",
                "enabled": true,
                "ecmpenabled": true,
                "bgp_neighbors": {
                    "1": {
                        "keepalivetimer": 60,
                        "holddowntimer": 180,
                        "remoteas": "100",
                        "peer": {
                            "name": "r1",
                            "label": "r2-peer",
                            "addr_type": "ipv4",
                        }
                    },
                    "2": {
                        "keepalivetimer": 60,
                        "holddowntimer": 180,
                        "remoteas": "100",
                        "peer": {
                            "name": "r3",
                            "label": "r2-peer",
                            "addr_type": "ipv4",
                        }
                    }

                },
                "gracefulrestart":true
         }
    },
    ...
```

- User can add as many routers as per the topology requirement in "routers" dictionary.
- "links" will define how particular router is connected to other routers.
- "bgp" has bgp configuration for each router
- "bgp_neighbors" will define how many neighbours are there for particular router.
- "label" will be used to identify which link needs to be used to connect particular router to its neighbour.
   label will be matched in peer's links. To whichever link label is matched, with that bgp neighborship will be established.
- "addr_type" will be used to select ip type, ipv4/ipv6

To establish bgp neighborship with loopback interface we are adding "source": "lo" inside "peer" as part of test case.
if source is added and its value is "lo" then bgp neighborship will be done using loopback interface.
       

### Creating dynamic topology
Read json file in test_frr_bgp_topo1.py and pass it to library: frr_bgp_helper.py api build_topo_json().

-- check API build_topo_json() for more details


### How to start and bring down the topology
Topology would be created in setup_module() but it will not be started until we load zebra.conf and bgpd.conf to router.

Inside setup_module, folders will be created for routers in CWD and zebra.conf and bgpd.conf files will be created inside router folder. These config file are loaded to all routers.

def setup_module(mod):
    ...

    # This function initiates the topology build with Topogen...
    tgen = Topogen(FoldedClosTopo, mod.__name__)
    # ... and here it calls Mininet initialization functions.

    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.iteritems():
        os.chdir(CWD)
        os.mkdir('{}'.format(rname))
        os.chdir("{}/{}".format(CWD, rname))
        os.system('touch zebra.conf bgpd.conf')

In addition to these mandatory file, router configuration files will also be created run time to respective router folder ex- frr.sav, frr.conf and delta.conf files.  

These file will be deleted automatically on teardown_module():

def teardown_module(mod):
    ....
    # Removing tmp files
    router_list = tgen.routers()
    for rname, router in router_list.iteritems():
        os.chdir(CWD)
        os.system("rm -rf {}".format(rname))


### Creating dynamic configuration (interfaces, protocol)

In library, helper classes are created for each interface/protocol configuration.

Example: creation of bgp configuration:

Following code snippet taken from frr_bgp_helper.py file:

## RoutingPB class is made for backup purpose, suppose user creates  BGP config so first config will be stored into FRRConfig.routingPB.bgp_config then it will be saved to FRRConfig. Use of keeping data in RoutingPB class is, if FRRConfig is reset for any router then the configuration can be retained back from  RoutingPB class variables.
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

## FRRConfig class is used to save all config FRRConfig variables and these variable data is read and printed to frr.conf file.
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

### Executing Tests
To run the whole suite of tests the following commands to be executed at the top level directory of topotest:

```shell
$ # Change to the top level directory of topotests.
$ cd path/to/frrtopotests
$ # Tests must be run as root, since Mininet requires it.
$ sudo pytest
```

In order to run a specific test, you can use the following command:

```shell
$ # running a specific topology
$ sudo pytest frr-bgp-topo1/
$ # or inside the test folder
$ cd frr-bgp-topo1
$ sudo pytest # to run all tests inside the directory
$ sudo pytest test_bgp_convergence_.py # to run a specific test
$ # or outside the test folder
$ cd ..
$ sudo pytest frr-bgp-topo1/test_frr_bgp_topo1.py # to run a specific one
```

The output of the tested daemons will be available at the temporary folder of
your machine:

```shell
$ ls /tmp/topotest/frr-bgp-topo1.test_frr_bgp_topo1/r1
...
zebra.err # zebra stderr output
zebra.log # zebra log file
zebra.out # zebra stdout output
...
```

### Logging of testcases executions
To enable logging of testcase executions messages into log file user has to enable frrtest_log_dir in pytest.ini file:
```
pytest.ini`:

[topogen]
### By default logs will be displayed to console, enable the below line to save execution logs to log file
frrtest_log_dir = /tmp/topotests/
```

Log file name will be displayed when we start execution:
root@test:~/frrtopotests/frr-bgp-topo1# python test_frr_bgp_topo1.py 
Logs will be sent to logfile: /tmp/topotests/test_frr_bgp_11:57:01.353797

###  TODO:
1. Add support to generate ips for any mask givem as of today "generate_ips" api supports ip_mask with 32.
2. Add support for multiple loopback addresses.


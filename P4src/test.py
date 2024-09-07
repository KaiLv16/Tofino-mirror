import logging
import grpc
import time
import sys

from ptf import config
from ptf.thriftutils import *
import ptf.testutils as testutils
from ptf.testutils import *
from bfruntime_client_base_tests import BfRuntimeTest, BaseTest
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as gc
import google.rpc.code_pb2 as code_pb2
from functools import partial
import random

swports = [142,141,192]

EGRESS_PORT_INVALID = 511

if test_param_get("arch") == "tofino":
    MIR_SESS_COUNT = 1024
    MAX_SID_NORM = 1015
    MAX_SID_COAL = 1023
    BASE_SID_NORM = 1
    BASE_SID_COAL = 1016
    EXP_LEN1 = 127
    EXP_LEN2 = 63
elif test_param_get("arch") == "tofino2":
    MIR_SESS_COUNT = 256
    MAX_SID_NORM = 255
    MAX_SID_COAL = 255
    BASE_SID_NORM = 0
    BASE_SID_COAL = 0
    EXP_LEN1 = 127
    EXP_LEN2 = 59
else:
    assert False, "Unsupported arch %s" % test_param_get("arch")

logger = logging.getLogger('Test')
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler())

def setup_random(seed_val=0):
    if 0 == seed_val:
        seed_val = int(time.time())
    logger.info("Seed is: %d", seed_val)
    sys.stdout.flush()
    random.seed(seed_val)

def program_mirror_fwd_table(self, target, port, egr_port=None, ing_mir=0, ing_sid=0, egr_mir=0, egr_sid=0):
    logger.info("Programming mirror forwarding table for the test...")
    if egr_port is None:
        egr_port = port

    self.mirror_fwd_table.entry_add(
        target,
        [self.mirror_fwd_table.make_key([gc.KeyTuple('ig_intr_md.ingress_port', port)])],
        [self.mirror_fwd_table.make_data([gc.DataTuple('dest_port', egr_port),
                                          gc.DataTuple('ing_mir', ing_mir),
                                          gc.DataTuple('ing_ses', ing_sid),
                                          gc.DataTuple('egr_mir', egr_mir),
                                          gc.DataTuple('egr_ses', egr_sid)],
                                         'SwitchIngress.set_md')]
    )


class TestIngMir(BfRuntimeTest):
    """
    Check that we can ingress mirror a packet out the port it came in on.
    """

    def setUp(self):
        client_id = 0
        p4_name = "lvkai_mirror"
        BfRuntimeTest.setUp(self, client_id, p4_name)
        
        self.bfrt_info = self.interface.bfrt_info_get(p4_name)
        self.gc = gc
        self.target = gc.Target(device_id=0, pipe_id=0xffff)
        # Get port table
        self.port_table = self.bfrt_info.table_get('$PORT')
        # Front-panel port to dev port lookup table
        self.port_hdl_info_table = self.bfrt_info.table_get('$PORT_HDL_INFO')
        # List of active ports
        self.active_ports = []

#-------------------------------- port related operation ------------------------------------------------
# get_dev_port(fp_port,lane)  输入前端PORT(port/lane)，返回D_P值
# add_port(fp_port, lane, speed, fec, an)  启用端口PORT，指定速率、纠错码、自动协商机制。
# remove_port(fp_port, lane)  关闭端口PORT
# add_ports(port_list)  批量开启端口，是add_port的封装
#---------------------------------------------------------------------------------------------------------
    def get_dev_port(self, fp_port, lane):
            ''' Convert front-panel port to dev port.

                Keyword arguments:
                    fp_port -- front panel port number
                    lane -- lane number

                Returns:
                    (success flag, dev port or error message)
            '''
            resp = self.port_hdl_info_table.entry_get(self.target, [
                self.port_hdl_info_table.make_key([
                    self.gc.KeyTuple('$CONN_ID', fp_port),
                    self.gc.KeyTuple('$CHNL_ID', lane)
                ])
            ], {'from_hw': False})

            try:
                dev_port = next(resp)[0].to_dict()['$DEV_PORT']
            except BfruntimeRpcException:
                return (False, 'Port {}/{} not found!'.format(fp_port, lane))
            else:
                return (True, dev_port)
    def add_port(self, front_panel_port, lane, speed, fec, an):
        ''' Add one port.

            Keyword arguments:
                front_panel_port -- front panel port number
                lane -- lane within the front panel port
                speed -- port bandwidth in Gbps, one of {10, 25, 40, 50, 100}
                fec -- forward error correction, one of {'none', 'fc', 'rs'}
                autoneg -- autonegotiation, one of {'default', 'enable', 'disable'}

            Returns:
                (success flag, None or error message)
        '''

        speed_conversion_table = {
            10: 'BF_SPEED_10G',
            25: 'BF_SPEED_25G',
            40: 'BF_SPEED_40G',
            50: 'BF_SPEED_50G',
            100: 'BF_SPEED_100G'
        }

        fec_conversion_table = {
            'none': 'BF_FEC_TYP_NONE',
            'fc': 'BF_FEC_TYP_FC',
            'rs': 'BF_FEC_TYP_RS'
        }

        an_conversion_table = {
            'default': 'PM_AN_DEFAULT',
            'enable': 'PM_AN_FORCE_ENABLE',
            'disable': 'PM_AN_FORCE_DISABLE',
            0: 'PM_AN_DEFAULT',
            1: 'PM_AN_FORCE_ENABLE',
            2: 'PM_AN_FORCE_DISABLE'
        }

        success, dev_port = self.get_dev_port(front_panel_port, lane)
        if not success:
            return (False, dev_port)

        if dev_port in self.active_ports:
            msg = 'Port {}/{} already in active ports list'.format(
                front_panel_port, lane)
            self.log.warning(msg)
            return (False, msg)

        self.port_table.entry_add(self.target, [
            self.port_table.make_key([self.gc.KeyTuple('$DEV_PORT', dev_port)])
        ], [
            self.port_table.make_data([
                self.gc.DataTuple('$SPEED',
                                  str_val=speed_conversion_table[speed]),
                self.gc.DataTuple('$FEC', str_val=fec_conversion_table[fec]),
                self.gc.DataTuple('$AUTO_NEGOTIATION',
                                  str_val=an_conversion_table[an]),
                self.gc.DataTuple('$PORT_ENABLE', bool_val=True)
            ])
        ])
        print(('Added port: {}/{} {}G {} {}'.format(
            front_panel_port, lane, speed, fec, an)))

        self.active_ports.append(dev_port)

        return (True, None)

    def remove_port(self, front_panel_port, lane):
        ''' Remove one port.

            Keyword arguments:
                front_panel_port -- front panel port number
                lane -- lane within the front panel port

            Returns:
                (success flag, None or error message)
        '''

        success, dev_port = self.get_dev_port(front_panel_port, lane)
        if not success:
            return (False, dev_port)

        # Remove on switch
        self.port_table.entry_del(self.target, [
            self.port_table.make_key([self.gc.KeyTuple('$DEV_PORT', dev_port)])
        ])

        print('Removed port: {}/{}'.format(front_panel_port, lane))

        # Remove from our local active port list
        self.active_ports.remove(dev_port)

        return (True, None)

    def add_ports(self, port_list):
        ''' Add ports.

            Keyword arguments:
                port_list -- a list of tuples: (front panel port, lane, speed, FEC string, autoneg) where:
                 front_panel_port is the front panel port number
                 lane is the lane within the front panel port
                 speed is the port bandwidth in Gbps, one of {10, 25, 40, 50, 100}
                 fec (forward error correction) is one of {'none', 'fc', 'rs'}
                 autoneg (autonegotiation) is one of {'default', 'enable', 'disable'} or {0, 1, 2}

            Returns:
                (success flag, None or error message)
        '''

        for (front_panel_port, lane, speed, fec, an) in port_list:
            success, error_msg = self.add_port(front_panel_port, lane, speed,
                                               fec, an)
            if not success:
                return (False, error_msg)

        return (True, None)

    def runTest(self):
        ports = [
                    (2,0,10,'none',2),
                    (2,1,10,'none',2), # 141 -- 10.21.0.233-eth2-10.22.0.201
                    (2,2,10,'none',2), # 142 -- 10.21.0.230-eth2-10.22.0.200
                    (2,3,10,'none',2)
                    
                ]
        self.add_ports(ports)
        
        '''
        @brief This test does the following:
          - Randomly selects a mirror session id for each port in the test
          - Adds a mirror forwarding table entry with egress port set to an
            invalid port for normal packet forwarding and enables ingress
            mirroring for the port's mirror session id
          - Sends a packet to each port and verifies that the mirrored copy
            is received as expected and normal packet gets dropped
          - Disables each mirror session and sends a packet to each port
            and verifies that no packet is received on any port
          - Enables each mirror session and sends a packet to each port
            and verifies that mirrored copy is received on each port and
            no other copy is received
          - Disables each mirror session again and sends a packet to each port
            and verifies that no packet is received on any port
          - Enables each mirror session again and sends a packet to each port
            and verifies that mirrored copy is received on each port and
            no other copy is received
          - Deletes all mirror sessions
          - Creates each mirror session in disabled state and sends a packet
            to each port and verifies that no packet is received on any port
          - Enables each mirror session again and sends a packet to each port
            and verifies that mirrored copy is received on each port and
            no other copy is received
          - Cleans up the test by deleting all mirror forwarding table
            entries and mirror session tables config
        '''
        logger.info("=============== Testing Basic Ingress Mirroring ===============")

        bfrt_info = self.interface.bfrt_info_get("lvkai_mirror")

        mirror_cfg_table = bfrt_info.table_get("$mirror.cfg")
        self.mirror_fwd_table = bfrt_info.table_get("mirror_fwd")
        target = gc.Target(device_id=0, pipe_id=0xffff)
        setup_random()
        self.sids = []

        # Cleanup all the config
        # Delete the mirror forwarding table entries
        #
        self.mirror_fwd_table.entry_del(target)
        #mirror_cfg_table.entry_del(target)   # cfg_table do not support this way to delete all entry

        # Verify mirror session config using wildcard entry get
        logger.info("Verifying entry get using Wildcard entry_get(target)")
        resps = mirror_cfg_table.entry_get(target)
        for i in resps:
            self.sids.append(i[1].to_dict()["$sid"]["value"])
        # Delete all mirror sessions
        while len(self.sids):
            sid = self.sids.pop(0)
            mirror_cfg_table.entry_del(
                target,
                [mirror_cfg_table.make_key([gc.KeyTuple('$sid', sid)])])

        # add mirror entry
        in_port = [141,142,192]
        sids = [1,2,3]
        out_port = [142,141,192]
        mirror_port = [141,141,192]
        for in_port, sid, out_port, mirror_port  in zip(in_port, sids, out_port, mirror_port):
            self.mirror_fwd_table.entry_add(
                target,
                [self.mirror_fwd_table.make_key([gc.KeyTuple('ig_intr_md.ingress_port', in_port)])],
                [self.mirror_fwd_table.make_data([gc.DataTuple('dest_port', out_port),
                                                gc.DataTuple('ing_mir', 1),
                                                gc.DataTuple('ing_ses', sid),
                                                gc.DataTuple('egr_mir', 0),
                                                gc.DataTuple('egr_ses', 0)],
                                                'SwitchIngress.set_md')]
            )
            
            mirror_cfg_table.entry_add(
                target,
                [mirror_cfg_table.make_key([gc.KeyTuple('$sid', sid)])],
                [mirror_cfg_table.make_data([gc.DataTuple('$direction', str_val="INGRESS"),
                                                gc.DataTuple('$ucast_egress_port', mirror_port),
                                                gc.DataTuple('$ucast_egress_port_valid', bool_val=True),
                                                gc.DataTuple('$session_enable', bool_val=True)],
                                            '$normal')]
            )
            self.sids.append(sid)
            logger.info("Using session %d for port %d, forward to %d & mirror to %d", sid, in_port, out_port, mirror_port)
            sys.stdout.flush()
        time.sleep(20)

# Test cases for message set pcep_1
import os, json, socket, time
from mamba import description, context, it, _it
from expects import expect, equal

from common.CommonUtils import *
# CSPLIST is defined in hw_disc.txt in JSON format, you can define any alias for the port, CSP1 and CSP2 is used for a B2B setup

pppox_mset_name = 'PPP_1'

controlType = {
    "UNDEFINED" : 0,
    "CONNECT" : 1,
    "DISCONNECT" : 2,
    "RETRY" : 3,
    "PAUSE" : 4,
    "RESUME" : 5,
    "TERMINATE" : 6,
}

ipcpMode = {
    "IPV4V6" : 0,
    "IPV4" : 1,
    "IPV6" : 2,
}

protocol = {
    "UNDEFINED" : 0,
    "PPPOPOS" : 1,
    "PPPOE" : 2,
    "PPPOEVLAN" : 3,
    "PPPOESVLAN" : 4,
    "PPPOL2TP" : 5,
    "PPPOEOA" : 6,
    "PPPOA" : 7,
}

RAMOFLAG = {
    "NODHCP"                      : 0,
    "REQUIRECONFIG"               : 1,
    "REQUIREDHCP"                 : 2,
}

sequenceType = {
    "SEQUENTIAL" : 0,
    "ROUND_ROBIN" : 1,
}

sessionState = {
    0 : "NONE",
    1 : "IDLE",
    2 : "CONNECTING",
    3 : "CONNECTING_FAILED",
    4 : "CONNECTED",
    5 : "DISCONNECTING",
}

with description('PPP_1:', 'access') as self:
    def sql_query(self, port, sqlcmd):
        pcepmset = get_port_msg_set(self, 'PPP_1', port)
        self.response = pcepmset.sendMessageGetResponse('DoSQL', {'commands':[sqlcmd]})

    def get_proto_config(self, proto):
        attr_name = 'pppBlockConfigParams'
        if proto.lower() == 'pppoe':
            attr_name = 'pppoeBlockConfigParams'
        elif proto.lower() == 'l2tp':
            attr_name = 'l2tpBlockConfiguredParams'
        else:
            assert proto.lower() == 'ppp'
        if not hasattr(self, attr_name):
            setattr(self, attr_name, [])
        return getattr(self, attr_name)
    def config_pppdevice(self, port):
        global pppox_mset_name
        ppp_mset = get_port_msg_set(self, self.msg_set_name, port)
        ifHandleList = [int(x) for x in [self.ifHandle[port]]]
        pppBlockConfigParams = self.get_proto_config('ppp')
        pppoeBlockConfigParams = self.get_proto_config('pppoe')
        l2tpBlockConfiguredParams = self.get_proto_config('l2tp')
        #print('======================{}'.format(pppBlockConfigParams))
        #print('======================{}'.format(pppoeBlockConfigParams))
        #print('======================{}'.format(l2tpBlockConfiguredParams))
        pppblkcfg = []
        pppoeblkcfg = []
        l2tpblkcfg = []
        handle = self.pppdevicehdls[port]
        for pppcfg in pppBlockConfigParams:
            if 'blockHandle' in pppcfg and pppcfg['blockHandle'] == int(handle):
                pppblkcfg.append(pppcfg)
        for pppoecfg in pppoeBlockConfigParams:
            if 'blockHandle' in pppoecfg and pppoecfg['blockHandle'] == int(handle):
                pppoeblkcfg.append(pppoecfg)
        for l2tpcfg in l2tpBlockConfiguredParams:
            if 'blockHandle' in l2tpcfg and l2tpcfg['blockHandle'] == int(handle):
                l2tpblkcfg.append(l2tpcfg)
        self.response = ppp_mset.sendMessageGetResponse('ConfigureBlocks',
                {
                    'ifHandleList' : ifHandleList,
                    'pppBlockConfigParams' : pppblkcfg,
                    'pppoeBlockConfigParams' : pppoeblkcfg,
                    'l2tpBlockConfiguredParams' : l2tpblkcfg
                }
            )

    def control_pppox(self, control, handles, mode, dis_or_not, port):
        global pppox_mset_name
        disconnectl2tp = True
        ppp_mset = get_port_msg_set(self, pppox_mset_name, port)
        assert control in controlType
        assert mode in ipcpMode
        if dis_or_not.upper() != 'DISCONNECT':
            disconnectl2tp = False

        self.response = ppp_mset.sendMessageGetResponse('ControlCommand', {"blockHandleMap": handles, "controlCmd": controlType[control], "ipcpMode": ipcpMode[mode], "l2tpSessionDisconnect": disconnectl2tp})

    with context('when a chassis/slot/port is given,'):
        with context('connect to the chassis and reserve the ports,'):
            with before.all:
                global protocol
                # using the first chassis/slot/port, in case you need more than 1 port
                self.msg_set_name = 'PPP_1'
                # need 2 ports
                self.chassis = ['172.18.0.2', '172.18.0.3']
                self.slot = ['1', '1']
                self.port = ['1', '1']
                self.TotalCount = 1
                self.portcount = 2
                #self.capture_mode = None
                # Get setup from env
                if os.environ.has_key('CSP1'):
                    (self.chassis[0], self.slot[0], self.port[0]) = get_csp_info('CSP1')
                if os.environ.has_key('CSP2'):
                    (self.chassis[1], self.slot[1], self.port[1]) = get_csp_info('CSP2')
                # conn and is a MUST for reserve port
                self.conn = [connect_chassis(self.chassis[0])]
                self.conn.append(connect_chassis(self.chassis[1]))
                # you MUST create portgroup to send message to the ccpu
                self.portgroup = [devices.deviceFactory(self.chassis[0], int(self.slot[0])-1, int(self.port[0]))]
                self.portgroup.append(devices.deviceFactory(self.chassis[1], int(self.slot[1])-1, int(self.port[1])))
                get_port_msg_set(self, self.msg_set_name, 0)
                get_port_msg_set(self, self.msg_set_name, 1)
                self.capture_file = os.path.join('.', 'ppp_capture'+'_'+time.strftime('%Y%m%d%H%M%S') + '.pcap')
                self.response = None
                self.ifHandle = [1, 2]
                # you SHOULD reserve portgroup to for cleanup in regression but not necessary in your new feature development
                print('Reserving ports...')
                self.reservedports = reserve_port(self, self.conn[0], int(self.slot[0]), int(self.port[0]))
                expect(self.reservedports).to(equal(True))
                result = reserve_port(self, self.conn[1], int(self.slot[1]), int(self.port[1]))
                expect(result).to(equal(True))
                self.pppdevicehdls = [1, 2]
                self.pppBlockConfigParams = [{"blockHandle": self.pppdevicehdls[0], "objectHandle": 1235, "ilHandleList": [], "sessionCount": 1, "protocol": protocol["PPPOE"], "mruNegEnabled": True, "magicEnabled": True, "ncpTerminationEnabled": False, "ACCMenabled": False, "papEnabled": False, "chapEnabled": False, "chapIncludeId": True, "ipv4Enabled": True, "ipv6Enabled": False, "osiEnabled": False, "mplsEnabled": False, "mruSize": 1492, "mruMaxSize": 65535, "echoReqEnabled": False, "echoReqGenPeriod": 10, "echoReqMaxAttempts": 0, "lcpACCMvalue": 0, "lcpConfReqTimeout": 3, "lcpConfReqMaxAttempts": 10, "lcpTermReqTimeout": 3, "lcpTermReqMaxAttempts": 10, "ncpConfReqTimeout": 3, "ncpConfReqMaxAttempts": 10, "maxNaks": 5, "papReqTimeout": 0, "papReqMaxAttempts": 57196, "papPeerReqTimeout": 3, "chapChalReqTimeout": 36912, "chapReplyTimeout": 3, "chapAckTimeout": 63896, "chapReqMaxChalAttempts": 10, "chapReqMaxReplyAttempts": 1, "autoRetryCount": 0, "autoRetry": True, "sessionAutoRetry": False, "specifiedClientIpAddrEnabled": False, "userName": "spirent", "password": "spirent", "useAuthenticationList": False, "userNameList": [], "passwordList": [], "enablePrimaryDns": True, "primaryDns": [], "enableSecondaryDns": True, "secondaryDns": [], "userNameHasWildcard": True, "passwordHasWildcard": True, "lcpDelay": 0, "enableAutoFillIpv6": False, "RAMOFlag": RAMOFLAG["NODHCP"], "ipV4Start": {"address": [192, 85, 1, 3]}, "ipV4Step": {"address": [0, 0, 0, 1]}, "ipV4Count": 1, "ipV4PoolStart": {"address": [192, 0, 1, 0]}, "ipV4PoolStep": {"address": [0, 0, 0, 1]}, "ipV4PoolCount": 10, "ipV6Start": {"address": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]}, "ipV6Step": {"address": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]}, "ipV6Count": 0, "ipV6PoolStart": {"address": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]}, "ipV6PoolStep": {"address": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]}, "ipV6IntfId": {"address": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]}, "ipV6IntfIdStep": {"address": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]}, "ipV6PoolCount": 0, "unconnectedSessionThreshold": 0, "serverInactivityTimer": 30, "connectRate": 100, "disconnectRate": 100, "ipV6Prefix": {"address": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]}, "optionList": []},
                                             {"blockHandle": self.pppdevicehdls[1], "objectHandle": 1235, "ilHandleList": [], "sessionCount": 1, "protocol": protocol["PPPOE"], "mruNegEnabled": True, "magicEnabled": True, "ncpTerminationEnabled": False, "ACCMenabled": False, "papEnabled": False, "chapEnabled": False, "chapIncludeId": True, "ipv4Enabled": True, "ipv6Enabled": False, "osiEnabled": False, "mplsEnabled": False, "mruSize": 1492, "mruMaxSize": 65535, "echoReqEnabled": False, "echoReqGenPeriod": 10, "echoReqMaxAttempts": 0, "lcpACCMvalue": 0, "lcpConfReqTimeout": 3, "lcpConfReqMaxAttempts": 10, "lcpTermReqTimeout": 3, "lcpTermReqMaxAttempts": 10, "ncpConfReqTimeout": 3, "ncpConfReqMaxAttempts": 10, "maxNaks": 5, "papReqTimeout": 0, "papReqMaxAttempts": 57196, "papPeerReqTimeout": 3, "chapChalReqTimeout": 36912, "chapReplyTimeout": 3, "chapAckTimeout": 63896, "chapReqMaxChalAttempts": 10, "chapReqMaxReplyAttempts": 1, "autoRetryCount": 0, "autoRetry": True, "sessionAutoRetry": False, "specifiedClientIpAddrEnabled": False, "userName": "spirent", "password": "spirent", "useAuthenticationList": False, "userNameList": [], "passwordList": [], "enablePrimaryDns": True, "primaryDns": [], "enableSecondaryDns": True, "secondaryDns": [], "userNameHasWildcard": True, "passwordHasWildcard": True, "lcpDelay": 0, "enableAutoFillIpv6": False, "RAMOFlag": RAMOFLAG["NODHCP"], "ipV4Start": {"address": [192, 85, 1, 4]}, "ipV4Step": {"address": [0, 0, 0, 1]}, "ipV4Count": 1, "ipV4PoolStart": {"address": [192, 0, 1, 0]}, "ipV4PoolStep": {"address": [0, 0, 0, 1]}, "ipV4PoolCount": 10, "ipV6Start": {"address": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]}, "ipV6Step": {"address": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]}, "ipV6Count": 0, "ipV6PoolStart": {"address": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]}, "ipV6PoolStep": {"address": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]}, "ipV6IntfId": {"address": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]}, "ipV6IntfIdStep": {"address": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]}, "ipV6PoolCount": 0, "unconnectedSessionThreshold": 0, "serverInactivityTimer": 30, "connectRate": 100, "disconnectRate": 100, "ipV6Prefix": {"address": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]}, "optionList": []},]
                
                self.pppoeBlockConfigParams = [{"blockHandle": self.pppdevicehdls[0], "maxPayloadTagEnable": False, "maxPayloadBytes": 1500, "padiTimeout": 0, "padiMaxAttempts": 0, "padrTimeout": 0, "padrMaxAttempts": 0, "svcName": "", "acName": "SpirentTestCenter", "echoVendorSpecificTagInPado": False, "echoVendorSpecificTagInPads": False, "enableRelayAgent": False, "relayAgentType": "DSL_FORUM", "circuitId": "circuit @s", "remoteOrSessionId": "remote @m-@p-@b", "relayAgentMacAddr": {"address": [0, 0, 0, 0, 0, 0]}, "relayAgentMacAddrStep": {"address": [0, 0, 0, 0, 0, 1]}, "relayAgentMacAddrMask": {"address": [255, 255, 255, 255, 255, 255]}, "includeRelayAgentInPADI": False, "includeRelayAgentInPADR": False, "ethIIInterface": {"NetworkInterface": {"EmulatedIf": {"NetworkEndpoint": {}, "IsRange": True, "IsDirectlyConnected": True, "IsRealism": False}, "IfCountPerLowerIf": 1, "IfRecycleCount": 0, "TotalCount": 10, "BllHandle": 6684, "AffiliatedInterface": 0}, "SourceMac": {"address": [0, 16, 149, 0,  0, 1]}, "SrcMacStep": {"address": [0, 0, 0, 0, 0, 1]}, "SrcMacList": [], "SrcMacStepMask": {"address": [0, 0, 255, 255, 255, 255]}, "SrcMacRepeatCount": 0, "VpnSiteType": 6, "VpnSiteId": 9043968}, "tagList": []},
                                               {"blockHandle": self.pppdevicehdls[1], "maxPayloadTagEnable": False, "maxPayloadBytes": 1500, "padiTimeout": 0, "padiMaxAttempts": 0, "padrTimeout": 0, "padrMaxAttempts": 0, "svcName": "", "acName": "SpirentTestCenter", "echoVendorSpecificTagInPado": False, "echoVendorSpecificTagInPads": False, "enableRelayAgent": False, "relayAgentType": "DSL_FORUM", "circuitId": "circuit @s", "remoteOrSessionId": "remote @m-@p-@b", "relayAgentMacAddr": {"address": [0, 0, 0, 0, 0, 0]}, "relayAgentMacAddrStep": {"address": [0, 0, 0, 0, 0, 1]}, "relayAgentMacAddrMask": {"address": [255, 255, 255, 255, 255, 255]}, "includeRelayAgentInPADI": False, "includeRelayAgentInPADR": False, "ethIIInterface": {"NetworkInterface": {"EmulatedIf": {"NetworkEndpoint": {}, "IsRange": True, "IsDirectlyConnected": True, "IsRealism": False}, "IfCountPerLowerIf": 1, "IfRecycleCount": 0, "TotalCount": 10, "BllHandle": 6684, "AffiliatedInterface": 0}, "SourceMac": {"address": [0, 16, 149, 0, 16, 1]}, "SrcMacStep": {"address": [0, 0, 0, 0, 0, 1]}, "SrcMacList": [], "SrcMacStepMask": {"address": [0, 0, 255, 255, 255, 255]}, "SrcMacRepeatCount": 0, "VpnSiteType": 6, "VpnSiteId": 9043968}, "tagList": []},
                                               ]
                self.l2tpBlockConfiguredParams = []

                ethinter = make_default_eth_interface(self.TotalCount, srcmac_str = '00:10:94:00:00:01', srcmacstep_str = '00:00:00:00:00:01')
                pppoeinter = make_pppoe_interfacelist(self.TotalCount)
                ifStack = add_upper_layer(ethinter, 'PPPOE', pppoeinter)
                # ip string is in unicode string, aka u'127.0.0.1'
                ipinter  = make_ipv4_interfacelist(self.TotalCount, ipaddress = u'192.85.0.3', plen = 16, gateway = u'192.85.1.4')
                ifStack = add_upper_layer(ethinter, 'IPv4', ipinter)
                config_interface(self, ifHandle = self.ifHandle[0], ifStack = ifStack, port = 0)

                ethinter = make_default_eth_interface(self.TotalCount, srcmac_str = '00:10:94:00:10:02', srcmacstep_str = '00:00:00:00:00:01')
                pppoeinter = make_pppoe_interfacelist(self.TotalCount)
                ifStack = add_upper_layer(ethinter, 'PPPOE', pppoeinter)
                # ip string is in unicode string, aka u'127.0.0.1'
                ipinter  = make_ipv4_interfacelist(self.TotalCount, ipaddress = u'192.85.1.4', plen = 16, gateway = u'192.85.0.3')
                ifStack = add_upper_layer(ethinter, 'IPv4', ipinter)
                config_interface(self, ifHandle = self.ifHandle[1], ifStack = ifStack, port = 1)

                # you SHOULD start analyzer to receive packets
                start_analyzer(self, 0)
                self.capture_config = config_capture(self, 'REALTIME_DISABLE', 'REGULAR_MODE', 'TX_RX_MODE', 'REGULAR_FLAG_MODE', 'WRAP')
                cp_mset = get_port_msg_set(self, Capture_mset, 0)
                self.response = cp_mset.sendMessageGetResponse('SetCaptureCfg', self.capture_config)
                start_analyzer(self, 1)

            with it('configs ppp client port parameters for port 1,'):
                global sequenceType
                portindex = 0
                enableBlockRate = False
                clientMode = True
                sequence = 'SEQUENTIAL'
                conrate = 100
                disrate = 1000
                outstanding = 1000
                portPcHandle = 5234
                posPcHandle = 5236
                port_name = 'AAT Port 1'
                assert sequence in sequenceType
                portconfig = {"portConfigParams": {"enableBlockRate": enableBlockRate, "connectRate": int(conrate), "disconnectRate": int(disrate), "maxOutstandingSessions": int(outstanding), "clientMode": clientMode, "sequence": sequenceType[sequence], "portPcHandle": int(portPcHandle), "posPcHandle": int(posPcHandle), "portName": port_name}}
                ppp_mset = get_port_msg_set(self, self.msg_set_name, portindex)
                self.response = ppp_mset.sendMessageGetResponse('ConfigurePort', portconfig)

            with it('configs ppp server port parameters for port 2,'):
                global sequenceType
                portindex = 1
                enableBlockRate = False
                clientMode = False
                sequence = 'SEQUENTIAL'
                conrate = 100
                disrate = 1000
                outstanding = 1000
                portPcHandle = 5234
                posPcHandle = 5236
                port_name = 'AAT Port 2'
                assert sequence in sequenceType
                
                portconfig = {"portConfigParams": {"enableBlockRate": enableBlockRate, "connectRate": int(conrate), "disconnectRate": int(disrate), "maxOutstandingSessions": int(outstanding), "clientMode": clientMode, "sequence": sequenceType[sequence], "portPcHandle": int(portPcHandle), "posPcHandle": int(posPcHandle), "portName": port_name}}
                ppp_mset = get_port_msg_set(self, self.msg_set_name, portindex)
                self.response = ppp_mset.sendMessageGetResponse('ConfigurePort', portconfig)

            with it('configs ppp client device for port 1,'):
                portindex = 0
                attach_interface(self, self.ifHandle[portindex], portindex, self.msg_set_name) #self.ifHandle[0]

                #print('Press any key to continue...')
                #stra = raw_input()
                self.config_pppdevice(portindex)

            with it('configs ppp client device for port 2,'):
                portindex = 1
                attach_interface(self, self.ifHandle[portindex], portindex, self.msg_set_name) #self.ifHandle[0]

                #print('Press any key to continue...')
                #stra = raw_input()
                self.config_pppdevice(portindex)

            with it('config capture with default and start capture before start devices on port 1,'):
                portindex = 0
                #capture_default(self, 'TX_RX', portindex)
                
                #config = config_capture(self, 'REALTIME_DISABLE', 'REGULAR_MODE', source_mode, 'REGULAR_FLAG_MODE', 'WRAP')
                cp_mset = get_port_msg_set(self, Capture_mset, portindex)
                self.response = cp_mset.sendMessageGetResponse('SetCaptureCfg', self.capture_config)

                start_capture(self, portindex)

            with it('connect ppp client device for port 2,'):
                portindex = 1
                #print('Press any key to continue...')
                #stra = raw_input()
                self.control_pppox('CONNECT', [self.pppdevicehdls[portindex]], 'IPV4V6', 'DISCONNECT', portindex)

            with it('connect ppp client device for port 1,'):
                portindex = 0
                #print('Press any key to continue...')
                #stra = raw_input()
                self.control_pppox('CONNECT', [self.pppdevicehdls[portindex]], 'IPV4V6', 'DISCONNECT', portindex)
                time.sleep(3)

            with it('TERMINATE ppp client device for port 1,'):
                portindex = 0
                #print('Press any key to continue...')
                #stra = raw_input()
                self.control_pppox('TERMINATE', [self.pppdevicehdls[portindex]], 'IPV4V6', 'DISCONNECT', portindex)

            with it('TERMINATE ppp client device for port 2,'):
                portindex = 1
                #print('Press any key to continue...')
                #stra = raw_input()
                self.control_pppox('TERMINATE', [self.pppdevicehdls[portindex]], 'IPV4V6', 'DISCONNECT', portindex)

            with it('stop capture after stopping devices,'):
                portindex = 0
                stop_capture(self, portindex)

            with it('save captured packets,'):
                portindex = 0
                first_packet = 0
                total = get_captured_packet_count(self, portindex)
                if total > 0:
                    get_captured_packets(self, 'ALL', first_packet, portindex)
                    save_capture_packets(self, self.capture_file, 'ETHERNET')
                else:
                    print('\nNo packet captured!')

            with after.all:
                # release for cleanup
                # wait for input
                #print('Press any key to continue...')
                #stra = raw_input()
                if self.reservedports:
                    for i in range(self.portcount):
                        response = release_port(self, self.conn[i], self.slot[i], self.port[i])

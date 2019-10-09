# Test cases for message set pcep_1
import os, json, socket, time
from mamba import description, context, it, _it
from expects import expect, equal

from common.CommonUtils import *
# CSPLIST is defined in hw_disc.txt in JSON format, you can define any alias for the port, CSP1 and CSP2 is used for a B2B setup

PCEP_STATE = {
    0:"NONE",
    1:"IDLE",
    2:"TCPPENDING",
    3:"OPENWAIT",
    4:"KEEPWAIT",
    5:"SESSIONUP",
}

with description('PCEP_1:', 'routing') as self:
    def config_pcep_device(self, mode, bllHandle, ifHandle, port, peer_ip):
        # mode = 1 PCC
        # mode = 2 PCE
        pr_ip = ips_2_address(peer_ip)
        device = self.portgroup[port]
        pname = 'Port //' + device.chassis.ipaddr + '/' + str(device.slot+1) + '/' + str(device.cpuid)
        #print('============={}'.format(pname))
        sessioncfg = {"BlockCfg": [{"Handle": bllHandle, "BlockCfg": {"IfHandleList": [ifHandle], "PcepMode": 2, "PcepDeviceRole": 0, "IpVersion": 0, "PeerIpv4Addr": {"address": pr_ip}, "PeerIpv4AddrStep": {"address": [0, 0, 0, 1]}, "PeerIpv6Addr": {"address": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]}, "PeerIpv6AddrStep": {"address": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]}, "PcepSessionIpAddress": 0, "IsSessionInitiator": True, "IsFixedSrcPort": False, "IsFixedDstPort": True, "CustomDstPort": 4189, "EnableNegotiation": True, "KeepAliveTimer": 30, "MinAccKeepAliveTimer": 0, "MaxAccKeepAliveTimer": 255, "DeadTimer": 90, "MinAccDeadTimer": 0, "MaxAccDeadTimer": 255, "EnablePCResults": False, "Authentication": 0, "Password": "Spirent", "SyncTimer": 60, "EnableStateful": True, "PcepCapability": 5, "EnableInitLsp": True, "EnableSegmentRouting": True, "SrPFlag": False, "SrNFlag": True, "SrLFlag": True, "MaxSIDDepth": 0, "UseCustomMessage": False, "OpenDelay": 0, "Ipv4Tos": 192, "Ipv6TrafficClass": 0, "Ttl": 64, "SpeakerEntityID": "", "EnableDBVersionTlv": False, "DBVersionStart": 1, "PortName": pname, "PathSetupTypes": [0, 1]}, "CustomPdu": [], "CustomObjectsVec": [], "OpenCfg": [{"ObjectType": 1, "ObjectHandle": 0}], "KeepaliveCfg": [], "AssociationGroup": [], "PstCustomTlv": [], "AssociationType": []}]}
        pcepmset = get_port_msg_set(self, 'PCEP_1', port)
        self.response = pcepmset.sendMessageGetResponse('ConfigPcepBlocks', sessioncfg)
    def sql_query(self, port, sqlcmd):
        pcepmset = get_port_msg_set(self, 'PCEP_1', port)
        self.response = pcepmset.sendMessageGetResponse('DoSQL', {'commands':[sqlcmd]})

    with context('when a chassis/slot/port is given,'):
        with context('connect to the chassis and reserve the ports,'):
            with before.all:
                # using the first chassis/slot/port, in case you need more than 1 port
                self.msg_set_name = 'PCEP_1'
                # need 2 ports
                self.chassis = ['172.18.0.2', '172.18.0.3']
                self.slot = ['1', '1']
                self.port = ['1', '1']
                self.TotalCount = 1
                self.portcount = 2
                self.capture_file = os.path.join('.', 'pcep_capture'+'_'+time.strftime('%Y%m%d%H%M%S') + '.pcap')
                self.reservedports = False
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
                self.response = None
                self.ifHandle = [1, 2]
                # you SHOULD reserve portgroup to for cleanup in regression but not necessary in your new feature development
                print('Reserving ports...')
                self.reservedports = reserve_port(self, self.conn[0], int(self.slot[0]), int(self.port[0]))
                expect(self.reservedports).to(equal(True))
                result = reserve_port(self, self.conn[1], int(self.slot[1]), int(self.port[1]))
                expect(result).to(equal(True))
                self.pcepdevicehdls = [1234, 4321]
                ethinter = make_default_eth_interface(self.TotalCount, srcmac_str = '00:10:94:00:00:01', srcmacstep_str = '00:00:00:00:00:01')
                # ip string is in unicode string, aka u'127.0.0.1'
                ipinter  = make_ipv4_interfacelist(self.TotalCount, ipaddress = u'192.85.0.3', plen = 16, gateway = u'192.85.1.4')
                ifStack = add_upper_layer(ethinter, 'IPv4', ipinter)
                config_interface(self, ifHandle = self.ifHandle[0], ifStack = ifStack, port = 0)

                ethinter = make_default_eth_interface(self.TotalCount, srcmac_str = '00:10:94:00:00:02', srcmacstep_str = '00:00:00:00:00:01')
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

            with it('configs global parameters for port 1,'):
                pcep_1 = get_port_msg_set(self, self.msg_set_name, 0)
                cfg = {"GlobalCfg": {"OpenDelay": 100, "CloseDelay": 100, "SessionOutStanding": 100, "SessionRetryCount": 50, "SessionRetryInterval": 5, "RequestRetryCount": 100, "RequestRetryInterval": 30, "LSPPerMessage": 100, "TCPInterval": 30, "PacketAlignToMTU": False, "EnableTCPNoDelay": False, "AssociationObjectClass": 40, "UseSRDraft5": False, "AssociationTypeListTlvType": 200, "PpagAssociationType": 100, "PpagTlvType": 100, "PathSegmentTlvType": 80, "PathBindingTlvType": 81, "ScaleMode": False}}
                response = pcep_1.sendMessageGetResponse('ConfigPcepGlobal', cfg)
                expect(response).to(equal({}))

            with it('configs pcc device for port 1 without attach interface'):
                try:
                    portindex = 0
                    self.config_pcep_device(1, self.pcepdevicehdls[portindex], self.ifHandle[portindex], portindex, u'192.85.1.4')
                    expect(True).to(equal(False))
                except:
                    expect(True).to(equal(True))

            with it('configs pcc device for port 1 after attach interface,'):
                portindex = 0
                attach_interface(self, self.ifHandle[portindex], portindex, self.msg_set_name)
                self.config_pcep_device(1, self.pcepdevicehdls[portindex], self.ifHandle[portindex], portindex, u'192.85.1.4')

                expect(self.response).to(equal({}))

            with it('check the data in database of port 1,'):
                global PCEP_STATE
                portindex = 0
                sqlcmd = 'SELECT PrimaryHandle, State, TxPCRptCount, RxPCRptCount FROM PcepDeviceResults'
                self.sql_query(portindex, sqlcmd)
                results = self.response["results"]
                for result in results:
                    #print result
                    rows = result['rows']
                    expect(len(rows)).to(equal(1))
                    #assert len(rows) == 1
                    for row in rows:
                        stats_item = row['int64Values']
                        #print "======================================="
                        expect(len(stats_item)).to(equal(4))
                        #assert len(stats_item) == 4
                        expect(stats_item[1]).to(equal(1)) # IDLE
                        #assert stats_item[1] in PCEP_STATE
                        #print('PCEP device[{0}] is {1}'.format(stats_item[0], PCEP_STATE[stats_item[1]]))

            with it('configs global parameters for port 2,'):
                pcep_1 = get_port_msg_set(self, self.msg_set_name, 1)
                cfg = {"GlobalCfg": {"OpenDelay": 100, "CloseDelay": 100, "SessionOutStanding": 100, "SessionRetryCount": 50, "SessionRetryInterval": 5, "RequestRetryCount": 100, "RequestRetryInterval": 30, "LSPPerMessage": 100, "TCPInterval": 30, "PacketAlignToMTU": False, "EnableTCPNoDelay": False, "AssociationObjectClass": 40, "UseSRDraft5": False, "AssociationTypeListTlvType": 200, "PpagAssociationType": 100, "PpagTlvType": 100, "PathSegmentTlvType": 80, "PathBindingTlvType": 81, "ScaleMode": False}}
                response = pcep_1.sendMessageGetResponse('ConfigPcepGlobal', cfg)
                expect(response).to(equal({}))

            with it('configs pce device for port 2 after attach interface,'):
                portindex = 1
                attach_interface(self, self.ifHandle[portindex], portindex, self.msg_set_name)
                self.config_pcep_device(2, self.pcepdevicehdls[portindex], self.ifHandle[portindex], portindex, u'192.85.0.3')

                expect(self.response).to(equal({}))

            with it('config capture with default and start capture before start devices,'):
                portindex = 0
                #capture_default(self, 'TX_RX', portindex)
                
                #config = config_capture(self, 'REALTIME_DISABLE', 'REGULAR_MODE', source_mode, 'REGULAR_FLAG_MODE', 'WRAP')
                cp_mset = get_port_msg_set(self, Capture_mset, portindex)
                self.response = cp_mset.sendMessageGetResponse('SetCaptureCfg', self.capture_config)

                start_capture(self, portindex)
                
            with it('starts pce device for port 2,'):
                portindex = 1
                pcep_1 = get_port_msg_set(self, self.msg_set_name, portindex)
                #print("start pcc {}".format(self.pcepdevicehdls[portindex]))
                response = pcep_1.sendMessageGetResponse('StartPcepSessions', {"Handles": [self.pcepdevicehdls[portindex]]})

                expect(response).to(equal({}))

            with it('starts pcc device for port 1,'):
                global PCEP_STATE
                portindex = 0
                pcep_1 = get_port_msg_set(self, self.msg_set_name, portindex)
                #print("start pcc {}".format(self.pcepdevicehdls[portindex]))
                response = pcep_1.sendMessageGetResponse('StartPcepSessions', {"Handles": [self.pcepdevicehdls[portindex]]})
                expect(response).to(equal({}))
                time.sleep(3)
                sqlcmd = 'SELECT PrimaryHandle, State, TxPCRptCount, RxPCRptCount FROM PcepDeviceResults'
                self.sql_query(portindex, sqlcmd)
                results = self.response["results"]
                for result in results:
                    #print result
                    rows = result['rows']
                    expect(len(rows)).to(equal(1))
                    #assert len(rows) == 1
                    for row in rows:
                        stats_item = row['int64Values']
                        #print "======================================="
                        expect(len(stats_item)).to(equal(4))
                        #assert len(stats_item) == 4
                        expect(stats_item[1]).to(equal(5)) # UP
                        #assert stats_item[1] in PCEP_STATE
                        #print('PCEP device[{0}] is {1}'.format(stats_item[0], PCEP_STATE[stats_item[1]]))
            with it('stops pcc device for port 1,'):
                portindex = 0
                pcep_1 = get_port_msg_set(self, self.msg_set_name, portindex)
                response = pcep_1.sendMessageGetResponse('StopPcepSessions', {"Handles": [self.pcepdevicehdls[portindex]]})

            with it('stops pce device for port 2,'):
                portindex = 1
                pcep_1 = get_port_msg_set(self, self.msg_set_name, portindex)
                response = pcep_1.sendMessageGetResponse('StopPcepSessions', {"Handles": [self.pcepdevicehdls[portindex]]})

                expect(response).to(equal({}))

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

            with it('check captured packets, there should be 1 lsp packet,'):
                portindex = 0
                total = GetCaptureCount(self.capture_file, 'ip.src == 192.85.0.3 && pcep.msg == 10')
                expect(total).to(equal(1))

            with after.all:
                # release for cleanup
                if self.reservedports:
                    for i in range(self.portcount):
                        response = release_port(self, self.conn[i], self.slot[i], self.port[i])

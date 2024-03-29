# Test ceases for messageset admin_1
import os
from mamba import description, context, it
from expects import expect, equal

from common.CommonUtils import *
# CSPLIST is defined in hw_disc.txt in JSON format, you can define any alias for the port, CSP1 and CSP2 is used for a B2B setup

with description('Admin:', 'admin') as self:
    with context('when a chassis is given,'):
        with context('and connects to the chassis,'):
            with before.all: # Don't use multiple before.all/after.all(or .each) in different contexts, see https://github.com/nestorsalceda/mamba/issues/130 for details
                # using the first chassis/slot/port
                self.chassis = '172.18.0.2'
                self.slot = 1
                self.port = 1
                #print(os.environ)
                if os.environ.has_key('CSP1'):
                    (self.chassis, self.slot, self.port) = extract_chassis(os.environ['CSP1'])

                # conn and msg_set is a must for calling send_message
                self.conn = connect_chassis(self.chassis)
                self.msg_set_name = 'admin_1'
                self.reservedports = False
            with after.all: # Don't use multiple before.all/after.all(or .each) in different contexts, see https://github.com/nestorsalceda/mamba/issues/130 for details
                pass # The last test case  has released the port

            with it('gets port group type'):
                msg_name = 'admin_1.GetPortGroupType'
                msg_content = {"portGroup": [{"slot": -1, "portGroup": -1, "port": -1}]}
                resp_dict = send_msg(self, self.conn, msg_name, msg_content)
                portTypeList = resp_dict['pgTypeList']
                expect(portTypeList[0]['pgType']).to(equal('VM-1G-V1-1P'))

            with it('gets the port status'):
                msg_name = 'admin_1.GetPortGroupPortStatus'
                msg_content = {"portGroup": [{"slot": -1, "portGroup": -1, "port": -1}]}
                resp_dict = send_msg(self, self.conn, msg_name, msg_content)
                portStatusList = resp_dict["portStatusList"]
                speed = (portStatusList[0])["speed"]
                linkStatus = (portStatusList[0])["linkStatus"]
                expect(linkStatus).to(equal('Up') | equal('Down'))
                expect(speed).to(equal('1G'))

            with it('reserves a port'):
                self.reservedports = reserve_port(self, self.conn, self.slot, self.port)
                expect(self.reservedports).to(equal(True))
            
            with it('releases a port'):
                if self.reservedports:
                    result = release_port(self, self.conn, self.slot, self.port)

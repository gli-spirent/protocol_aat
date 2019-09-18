import os, sys, platform, time, pwd
import string, socket, struct, json, ipaddress
import subprocess

import RelativePathSetup

# CSPLIST is defined in hw_disc.txt in JSON format, you can define any alias for the port, CSP1 and CSP2 is used for a B2B setup

#import stc.utils
import mps.conn
import mps.idl
from stc import devices
from stc import utils
import msets.core as core

def _decode_list(data):
    rv = []
    for item in data:
        if isinstance(item, unicode):
            item = item.encode('utf-8')
        elif isinstance(item, list):
            item = _decode_list(item)
        elif isinstance(item, dict):
            item = _decode_dict(item)
        rv.append(item)
    return rv

def _decode_dict(data):
    rv = {}
    for key, value in data.iteritems():
        if isinstance(key, unicode):
            key = key.encode('utf-8')
        if isinstance(value, unicode):
            value = value.encode('utf-8')
        elif isinstance(value, list):
            value = _decode_list(value)
        elif isinstance(value, dict):
            value = _decode_dict(value)
        rv[key] = value
    return rv

def json_loads(data):
    return json.loads(data, object_hook=_decode_dict)

def extract_chassis(csp_string):
    csp = csp_string.lstrip('/')
    return csp.split('/')

def get_csp_info(csp_alias):
    if os.environ.has_key(csp_alias):
        (chassis, slot, port) = extract_chassis(os.environ[csp_alias])
        pn = int(port)
        if pn < 1 or pn > 8:
            raise ValueError('Port number {} should be 1 ~ 8'.format(port))
        sn = int(slot)
        if sn < 1 or sn > 12:
            raise ValueError('Slot number {} should be 1 ~ 12'.format(slot))
        return (chassis, slot, port)
    else:
        raise EnvironmentError('{} was not found in env.'.format(csp_alias))

# ips is in unicode string, aka u'127.0.0.1'
def ips_2_address(ips):
    ipadd = ipaddress.ip_address(ips)
    ipadds = struct.unpack('B'*len(ipadd.packed), ipadd.packed)
    return list(ipadds)

def macs_2_address(macs):
    macs = macs.replace('-', '.')
    macs = macs.replace(':', '.')
    madds = macs.split('.')
    macaddr = []
    if len(madds) == 3:
        for madd in madds:
            if len(madd) != 4: #0123.4567.89AB
                raise ValueError('Invalid mac address!', macs)
            macaddr.append(int(madd[:2], 16))
            macaddr.append(int(madd[2:], 16))
    elif len(madds) == 6:
        base = 16
        for madd in madds:
            if len(madd) > 3: #01:23:45:67:89:AB
                raise ValueError('Invalid mac address!', macs)
            if len(madd) == 3 or len(madd) == 1:
                base = 10
                break
        for madd in madds:
            macaddr.append(int(madd, base))
    return macaddr

def GetCaptureCount(capFileName, Filter):
    total = 0
    if os.path.exists(capFileName):
        Path = os.path.dirname(capFileName)
        name = os.path.basename(capFileName)
        #stc.log('INFO', 'capFileNamePlusPath = :' + str(capFileNamePlusPath))

        #args = 'tshark -r ' + capFileName + ' -R ' + '\"' + Filter + '\"'
        args = 'tshark -r ' + '\"' + capFileName + '\"' + ' -Y ' + Filter
        #stc.log('INFO', 'args = ' + str(args))
        capoutput = os.path.join(Path,  os.path.splitext(name)[0] + '.txt')
        #stc.log('INFO', 'capoutput = :' + str(capoutput))
        log = open(capoutput, "w", 1)
        proc = subprocess.Popen(args , shell=True, stderr=subprocess.PIPE, stdout=log)
        return_code = proc.wait()
        #stc.log('INFO', 'return_code = ' + str(return_code))

        log.flush()
        log.close()
        if return_code != 0:
            raise Exception('Error running tshark command. Error' + proc.stderr)
        else:
            readfile = open(capoutput, "r", 1)
            total = sum(1 for line in readfile)

    return total

def make_device(chassis, slot, port):
    device = devices.deviceFactory(chassis, int(slot)-1, int(port))
    return device

def make_device_msgset(device, msg_set):
    return core.MessageSet(msg_set, device)    

def get_msg_set(context, msg_set):
    """
    Create the message set if needed and return it
    """
    if not hasattr(context, msg_set):
        setattr(context, msg_set, mps.idl.makeMessageSet(msg_set))
    return getattr(context, msg_set)

def get_port_msg_set(context, msg_set, portindex = 0):
    """
    Create the message set of ccpu if needed and return it
    """
    msg_attr = msg_set+'_' + str(portindex)
    if not hasattr(context, msg_attr):
        setattr(context, msg_attr, make_device_msgset(context.portgroup[portindex], msg_set))
    return getattr(context, msg_attr)

def send_msg(context, conn, msg, msg_dict):
    # without this we get weird unicode errors in phxrpc encoding
    msg = str(msg)
    msg_set_name, msg_name = msg.split('.')
    msg_set = get_msg_set(context, msg_set_name)
    req = msg_set.createRequest(msg_name, msg_dict)
    response = conn.sendRequestWaitResponse(req, port=0)
    
    return msg_set.parseResponse(msg_name, response)

def connect_chassis(chassis_ip):
    tcpPort = 40004
    conn = mps.conn.SyncConnection()
    conn.connect(chassis_ip, tcpPort)
    return conn

def reserve_port(context, conn, slot, portgroup):
    platf = platform.system()
    uid = 'aat-user'
    host = platform.node()
    pid = os.getpid()
    if platf == 'Linux':
        uid = pwd.getpwuid( os.getuid() ).pw_name
    elif platf == 'Windows':
        uid = os.getenv('username')
    else:
        print("OS: {} is not supported".format(platf))
    tm = time.ctime()
    admin_1 = get_msg_set(context, 'admin_1')
    userinfo = {"userName": uid, "hostname": host, "processId": "14276", "timestamp": tm}
    login = admin_1.createRequest('Login', {'user': userinfo})
    response = conn.sendRequestWaitResponse(login, port=0)
    response_dict = admin_1.parseResponse('Login', response)
    target = [{"slot": slot, "portGroup": portgroup, "port": 0}]
    revokeOwner = True
    #print(slot)
    login = admin_1.createRequest('Reserve', {'target':target, 'revokeOwner':revokeOwner})
    response = conn.sendRequestWaitResponse(login, port=0)
    response_dict = admin_1.parseResponse('Reserve', response)
    return response_dict

def release_port(context, conn, slot, portgroup):
    target = [{"slot": slot, "portGroup": portgroup, "port": 0}]
    mode = 'FULL'
    admin_1 = get_msg_set(context, 'admin_1')
    login = admin_1.createRequest('Release', {'target':target, 'mode':mode})
    response = conn.sendRequestWaitResponse(login, port=0)
    response_dict = admin_1.parseResponse('Release', response)
    return response_dict

InterfaceTypeList = {
    "IPv6"   : 0,
    "IPv4"   : 1,
    "ETHII"  : 2,
    "VLAN"   : 3,
    "MPLS"   : 4,
    "PPP"    : 5,
    "PPPOE"  : 6,
    "GRE"    : 7,
    "HDLC"   : 8,
    "WIMAX"  : 9,
    "L2TPv2" : 10,
    "L2TPv3" : 11,
    "ITAG"   : 12,
    "AAL5"   : 13,
    "FC"     : 14,
    "LISP"   : 15,
    "GIF"    : 16,
    "STF"    : 17,
    "TRILL"  : 18,
    "VXLAN"  : 19,
    "GROUP"  : 20,
}

InterfaceTypeMap = {
    "IPv6"   : "Ipv6InterfaceList",
    "IPv4"   : "Ipv4InterfaceList",
    "ETHII"  : "EthIIInterfaceList",
    "VLAN"   : "VlanInterfaceList",
    "MPLS"   : "MplsInterfaceList",
    "PPP"    : "PppInterfaceList",
    "PPPOE"  : "PppoeInterfaceList",
    "GRE"    : "GreInterfaceList",
    "HDLC"   : "HdlcInterfaceList",
    "WIMAX"  : "WimaxInterfaceList",
    "L2TPv2" : "L2tpv2InterfaceList",
    "L2TPv3" : "L2tpv3InterfaceList",
    "ITAG"   : "ItagInterfaceList",
    "AAL5"   : "Aal5InterfaceList",
    "FC"     : "FcInterfaceList",
    "LISP"   : "LispInterfaceList",
    #"GIF"    : "",
    #"STF"    : "",
    "TRILL"  : "TrillInterfaceList",
    "VXLAN"  : "VxlanInterfaceList",
    "GROUP"  : "GroupInterfaceList",
}

bllHandle = 1000
def make_default_eth_interface(TotalCount, srcmac_str, srcmacstep_str):
    global bllHandle
    srcmac = macs_2_address(srcmac_str)
    srcmacstep = macs_2_address(srcmacstep_str)
    ifStack = {"ifDescriptors": [{"ifType": "ETHII", "indexInList": 0}], "Ipv6InterfaceList": [], "Ipv4InterfaceList": [], "EthIIInterfaceList": [{"NetworkInterface": {"EmulatedIf": {"NetworkEndpoint": {}, "IsRange": True, "IsDirectlyConnected": True, "IsRealism": False}, "IfCountPerLowerIf": 1, "IfRecycleCount": 0, "TotalCount": TotalCount, "BllHandle": bllHandle, "AffiliatedInterface": 0}, "SourceMac": {"address": srcmac}, "SrcMacStep": {"address": srcmacstep}, "SrcMacList": [], "SrcMacStepMask": {"address": [0, 0, 255, 255, 255, 255]}, "SrcMacRepeatCount": 0, "VpnSiteType": 0, "VpnSiteId": 0}], "VlanInterfaceList": [], "MplsInterfaceList": [], "PppInterfaceList": [], "PppoeInterfaceList": [], "GreInterfaceList": [], "HdlcInterfaceList": [], "WimaxInterfaceList": [], "L2tpv2InterfaceList": [], "L2tpv3InterfaceList": [], "ItagInterfaceList": [], "Aal5InterfaceList": [], "FcInterfaceList": [], "LispInterfaceList": [], "TrillInterfaceList": [], "VxlanInterfaceList": [], "GroupInterfaceList": []}

    bllHandle += 1
    return ifStack

def make_ipv4_interfacelist(TotalCount, ipaddress, plen, gateway):
    global bllHandle
    ipaddr = ips_2_address(ipaddress)
    gwaddr = ips_2_address(gateway)
    ipinterfacelist = {"NetworkInterface": {"EmulatedIf": {"NetworkEndpoint": {}, "IsRange": True, "IsDirectlyConnected": True, "IsRealism": False}, "IfCountPerLowerIf": 1, "IfRecycleCount": 0, "TotalCount": TotalCount, "BllHandle": bllHandle, "AffiliatedInterface": 0}, "Address": {"address": ipaddr}, "AddrStep": {"address": [0, 0, 0, 1]}, "AddrStepMask": {"address": [255, 255, 255, 255]}, "SkipReserved": True, "AddrList": [], "AddrRepeatCount": 0, "PrefixLength": plen, "EnableGatewayLearning": False, "Gateway": {"address": gwaddr}, "GatewayStep": {"address": [0, 0, 0, 0]}, "GatewayRepeatCount": 0, "GatewayRecycleCount": 0, "GatewayList": [], "ResolveGatewayMac": True, "GatewayMac": {"address": [0, 0, 1, 0, 0, 1]}, "Ttl": 255, "Tos": 192, "Ipv4TunnelGateway": {"address": gwaddr}, "VpnSiteType": 0, "VpnSiteId": 0, "AddrIncrementPerRouter": 0}
    bllHandle += 1
    return ipinterfacelist

def make_pppoe_interfacelist(TotalCount):
    global bllHandle
    pppoeinterfacelist = {"NetworkInterface": {"EmulatedIf": {"NetworkEndpoint": {}, "IsRange": True, "IsDirectlyConnected": True, "IsRealism": False}, "IfCountPerLowerIf": 1, "IfRecycleCount": 0, "TotalCount": TotalCount, "BllHandle": bllHandle, "AffiliatedInterface": 0}, "SessionId": 0, "SessionIdStep": 0, "SessionIdList": [], "SessionIdRepeatCount": 0, "PeerMacAddr": {"address": [0, 0, 0, 0, 0, 0]}, "PeerMacAddrList": []}
    bllHandle += 1
    return pppoeinterfacelist


def add_upper_layer(ifStack, ifType, interfacelist):
    if ifType not in InterfaceTypeMap:
        #print('Not supported ifType: {}'.format(ifType))
        raise KeyError('Not supported ifType: {}'.format(ifType))
    interfacelistname = InterfaceTypeMap[ifType]
    ifDescriptors = ifStack["ifDescriptors"]
    ifDescriptors.append({"ifType": InterfaceTypeList[ifType], "indexInList": 0})
    iflist = ifStack[interfacelistname]
    iflist.append(interfacelist)

    return ifStack

def config_interface(context, ifHandle, ifStack, port):
    ilHandleList = [int(ifHandle)]

    ifStackList = [ifStack]
    optionList = [0]

    print("Setup a interface {}...".format(ifHandle))
    ifmgr_1 = get_port_msg_set(context, 'ifMgr_1', port)
    context.response = ifmgr_1.sendMessageGetResponse( 'ConfigInterfacesWithIlHandle', {"ilHandleList":ilHandleList, "ifStackList":ifStackList, "optionList":optionList})

def attach_interface(context, ifHandle, port, mset):
    msgset = get_port_msg_set(context, mset, port)
    context.response = msgset.sendMessageGetResponse( 'AttachInterfaces', {'ifHandleList':[int(ifHandle)]})

anaTimestampLatchMode = {
    "MIN" : 0,
    "START_OF_FRAME" : 1,
    "END_OF_FRAME" : 2,
    "MAX" : 3,
}

anaSignatureMode = {
    "MIN" : 0,
    "LONG_SEQUENCE_NUM" : 1,
    "ENHANCED_DETECTION" : 2,
    "MAX" : 3,
}

def start_analyzer(context, portid):
    ana = get_port_msg_set(context, 'Analyzer_2', portid)
    print("Starting Analyzer......")
    resp = ana.sendMessageGetResponse('GetRunState', {})
    #print resp
    stkey = 'isRunning'
    if stkey in resp:
        if resp[stkey] == 0:
            config = {"rxTimestampLatchMode": anaTimestampLatchMode["START_OF_FRAME"], "streamAssocCfg": ("dataFilter", {"comparator16": [{"enable": False, "location": ("vlanTag", {"index": 0}), "mask": 0, "startOfRange": 0, "endOfRange": 0, "filterChain": False}, {"enable": False, "location": ("vlanTag", {"index": 0}), "mask": 0, "startOfRange": 0, "endOfRange": 0, "filterChain": False}, {"enable": False, "location": ("vlanTag", {"index": 0}), "mask": 0, "startOfRange": 0, "endOfRange": 0, "filterChain": False}, {"enable": False, "location": ("vlanTag", {"index": 0}), "mask": 0, "startOfRange": 0, "endOfRange": 0, "filterChain": False}], "comparator32": {"enable": True, "location": ("spirentSignatureId", {}), "mask": 4294967295, "startOfRange": 0, "endOfRange": 4294967295}}), "histogramCfg": ("transferDelay", {"histLimits": [2, 6, 14, 30, 62, 126, 254, 510, 1022, 2046, 4094, 8190, 16382, 32766, 65534]}), "qbvFilters": [], "qbvBuckets": [], "diffServ": {"qualifyIPv6Dest": False, "qualifyIPv4Dest": False, "destIPv6Addr": [255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255], "destIPv4Addr": [0, 0, 0, 0]}, "counterParams": {"jumboThreshold": 1518, "oversizedThreshold": 9018, "undersizedThreshold": 64, "advSeqCheckerLateThreshold": 1000}, "signatureMode": anaSignatureMode["ENHANCED_DETECTION"], "latencyMode": False}
            context.response = ana.sendMessageGetResponse('SetCommonCfg', {'config':config})
            #print resp
            context.response = ana.sendMessageGetResponse('Control', {"action":"START"})
            #print resp
            context.response = ana.sendMessageGetResponse('GetRunState', {})
    return ana

cptr_slice = {
    "DISABLE" : 0,
    "ENABLE" : 1,
}

cptr_slice_offset = {
    "PREAMBLE" : 0,
    "FRAME" : 1,
    "IP" : 2,
    "IP_PAYLOAD" : 3,        
}

cptr_FilterMode = {
    "FRAME_CONTENT" : 0,
    "OFFSET_AND_RANGE" : 1,
    "IEEE80211_FRAME_MODE" : 2,
}

cptr_realtime_mode = {
    "REALTIME_DISABLE"   :0,
    "REALTIME_ENABLE"    :1,
    "REALTIME_MODE_COUNT":2,
}

cptr_mode = {
    "REGULAR_MODE"            :  0,
    "SIGNATURE_MODE"          :  1,
    "IEEE80211_MODE_RADIO"    :  2,
    "IEEE80211_MODE_CLIENT"   :  3,
    "MODE_COUNT"              :  4,
}

cptr_source_mode = {
    "TX_MODE"             :  1,
    "RX_MODE"             :  2,
    "TX_RX_MODE"          :  3,
    "SOURCE_MODE_COUNT"   :  4,
}

cptr_flag_mode = {
    "REGULAR_FLAG_MODE"   :  0,
    "ADV_SEQ_FLAG_MODE"   :  1,
    "FLAG_MODE_COUNT"     :  2,
}

cptr_rollover_mode = {
    "WRAP"                :  0,
    "STOP_ON_FULL"        :  1,
    "ROLLOVER_MODE_COUNT" :  2,
}

cptr_ctrl = {
    "STOP" : 0,
    "START" : 1,
}

cptr_clear = {
    "DONT_CLEAR" : 0,
    "CLEAR"      : 1,
}

cptr_Ieee80211_channelWidth = {
    "CHANNEL_WIDTH_20M" : 0,
    "CHANNEL_WIDTH_40M" : 1,
    "CHANNEL_WIDTH_80M" : 2,
    "CHANNEL_WIDTH_80M_80M" : 3,
    "CHANNEL_WIDTH_160M" : 4,
}

# http://www.tcpdump.org/linktypes.html
linktype_map = {
    'NULL' : 0,
    'ETHERNET' : 1,
    'AX25' : 3,
    'IEEE802_5' : 6,
    'ARCNET_BSD' : 7,
    'SLIP' : 8,
    'PPP' : 9,
    'FDDI' : 10,
    'PPP_HDLC' : 50,
    'PPP_ETHER' : 51,
    'ATM_RFC1483' : 100,
    'RAW' : 101,
    'C_HDLC' : 104,
    'IEEE802_11' : 105,
    'FRELAY' : 107,
    'LOOP' : 108,
    'LINUX_SLL' : 113,
    'LTALK' : 114,
    'PFLOG' : 117,
    'IEEE802_11_PRISM' : 119,
    'IP_OVER_FC' : 122,
    'SUNATM' : 123,
    'IEEE802_11_RADIOTAP' : 127,
    'ARCNET_LINUX' : 129,
    'APPLE_IP_OVER_IEEE1394' : 138,
    'MTP2_WITH_PHDR' : 139,
    'MTP2' : 140,
    'MTP3' : 141,
    'SCCP' : 142,
    'DOCSIS' : 143,
    'LINUX_IRDA' : 144,
    'USER' : 147,  # _USER0-_USER15' : 147-162,
    'IEEE802_11_AVS' : 163,
    'BACNET_MS_TP' : 165,
    'PPP_PPPD' : 166,
    'GPRS_LLC' : 169,
    'LINUX_LAPD' : 177,
    'BLUETOOTH_HCI_H4' : 187,
    'USB_LINUX' : 189,
    'PPI' : 192,
    'IEEE802_15_4' : 195,
    'SITA' : 196,
    'ERF' : 197,
    'BLUETOOTH_HCI_H4_WITH_PHDR' : 201,
    'AX25_KISS' : 202,
    'LAPD' : 203,
    'PPP_WITH_DIR' : 204,
    'C_HDLC_WITH_DIR' : 205,
    'FRELAY_WITH_DIR' : 206,
    'IPMB_LINUX' : 209,
    'IEEE802_15_4_NONASK_PHY' : 215,
    'USB_LINUX_MMAPPED' : 220,
    'FC_2' : 224,
    'FC_2_WITH_FRAME_DELIMS' : 225,
    'IPNET' : 226,
    'CAN_SOCKETCAN' : 227,
    'IPV4' : 228,
    'IPV6' : 229,
    'IEEE802_15_4_NOFCS' : 230,
    'DBUS' : 231,
    'DVB_CI' : 235,
    'MUX27010' : 236,
    'STANAG_5066_D_PDU' : 237,
    'NFLOG' : 239,
    'NETANALYZER' : 240,
    'NETANALYZER_TRANSPARENT' : 241,
    'IPOIB' : 242,
    'MPEG_2_TS' : 243,
    'NG40' : 244,
    'NFC_LLCP' : 245,
    'INFINIBAND' : 247,
    'SCTP' : 248,
    'USBPCAP' : 249,
    'RTAC_SERIAL' : 250,
    'BLUETOOTH_LE_LL' : 251,
    'NETLINK' : 253,
    'BLUETOOTH_LINUX_MONITOR' : 254,
    'BLUETOOTH_BREDR_BB' : 255,
    'BLUETOOTH_LE_LL_WITH_PHDR' : 256,
    'PROFIBUS_DL' : 257,
    'PKTAP' : 258,
    'EPON' : 259,
    'IPMI_HPM_2' : 260,
}

def save_capture(fname, packets, link_type = 'ETHERNET', cp_mod = 0, append2file = False, SaveBufferWithPreamble = False):
    def sortbytimestamp(val):
        return val['timestamp']

    _MAGIC = 0xA1B2C3D4
    caplen = 0
    dlen = 0
    SaveBufferWithPreamble = False
    little_endian = (sys.byteorder == 'little')

    _endian = '='
    magic = _MAGIC
    version_major = 2
    version_minor = 4
    thiszone = 0
    sigfigs = 0
    snaplen = 65535
    fmod = 'wb+'
    if append2file:
        fmod = 'a+'
    linktype = linktype_map['ETHERNET']
    link_type = link_type.upper()
    if link_type in linktype_map:
        linktype = linktype_map[link_type]

    pcap_file_hdr = struct.pack(_endian + 'IHHIIII',
                                magic, version_major, version_minor,
                                thiszone, sigfigs,
                                snaplen, linktype)

    pcap_file = open(fname, fmod)
    pcap_file.write(pcap_file_hdr)
    packets.sort(key = sortbytimestamp)
    for pkt in packets:
        pkt_hdr = ''
        if cp_mod == cptr_mode["REGULAR_MODE"]:
            if SaveBufferWithPreamble:
                caplen = pkt['streamId_dataLen']
            else:
                caplen = pkt['streamId_dataLen'] - pkt['preambleLength']
            if link_type == 'SUNATM':
                caplen -= (1+8)
        elif cp_mod == cptr_mode["SIGNATURE_MODE"]:
            caplen = 16
        elif cp_mod == cptr_mode["IEEE80211_MODE_RADIO"] or cp_mod == cptr_mode["IEEE80211_MODE_CLIENT"]:
            caplen = pkt['streamId_dataLen']
        else:
            raise ValueError('Unsupported capture mode!', str(cp_mod))
        if pkt['streamId_frameLen'] == 0:
            dlen = caplen
        else:
            dlen = pkt['streamId_frameLen']
        # No time ajust, CPTR_IEEE80211_MODE_RADIO, CPTR_IEEE80211_MODE_CLIENT not support
        tm = pkt['timestamp'] * 2.5
        tv_sec = int(tm/1E9)
        tv_usec = int(math.fmod(tm, 1E9))
        pkt_hdr = struct.pack('=IIII', tv_sec, tv_usec, caplen, dlen)
        #print(pkt['index'], tv_sec, tv_usec, caplen, dlen, pkt['preambleLength'], len(pkt['sig_data']), len(((pkt['sig_data'])[pkt['preambleLength']:])))
        pcap_file.write(pkt_hdr)
        if SaveBufferWithPreamble:
            pcap_file.write(pkt['sig_data'])
        else:
            pcap_file.write((pkt['sig_data'])[pkt['preambleLength']:])

    pcap_file.close()

Capture_mset = 'Capture_2'
def config_capture(context, realtime_mode, capture_mode, source_mode, flag_mode, rollover_mode, port):
    rt_mod = 0
    cp_mod = 0
    src_mod = 0
    fl_mod = 0
    rl_mod = 0
    if realtime_mode in cptr_realtime_mode:
        rt_mod = cptr_realtime_mode[realtime_mode]
    if capture_mode in cptr_mode:
        cp_mod = cptr_mode[capture_mode]
    if source_mode in cptr_source_mode:
        src_mod = cptr_source_mode[source_mode]
    if flag_mode in cptr_flag_mode:
        fl_mod = cptr_flag_mode[flag_mode]
    if rollover_mode in cptr_rollover_mode:
        rl_mod = cptr_rollover_mode[rollover_mode]

    if not hasattr(context, 'capture_mode'):
        setattr(context, 'capture_mode', cp_mod)
    else:
        context.capture_mode = cp_mod
    config = { 
        "config":{ 
            "realtime_mode":rt_mod,
            "capture_mode":cp_mod,
            "source_mode":src_mod,
            "flag_mode":fl_mod,
            "rollover_mode":rl_mod,
            "start_event_a":16384,
            "qualify_event_a":16384,
            "stop_event_a":0,
            "event_b":0,
            "slice_mode":cptr_slice[ "DISABLE" ],
            "slice_offset_ref":cptr_slice_offset[ "PREAMBLE" ],
            "slice_offset":0,
            "slice_byte":0,
            "matching_frame_length":0,
            "matching_stream_id":0,
            "matching_stream_id_mask":0,
            "post_stop_count":0,
            "buffer_size":0,
            "filter_mode":cptr_FilterMode[ "FRAME_CONTENT" ],
            "increased_memory_support":False,
            "Ieee80211_cfg":{ 
                "channelWidth":cptr_Ieee80211_channelWidth[ "CHANNEL_WIDTH_20M"],
                "channels":[]
            },
            "Ieee80211_filter_cfg":""
        }
    }

    return config

def capture_default(context, direction, port):
    source_mode = 'TX_RX_MODE'
    direction = direction.upper()
    if direction == 'TX':
        source_mode = 'TX_MODE'
    elif direction == 'RX':
        source_mode = 'RX_MODE'
    elif direction == 'COUNT':
        source_mode = 'SOURCE_MODE_COUNT'

    cp_mset = get_port_msg_set(context, Capture_mset, int(port))
    config = config_capture(context, 'REALTIME_DISABLE', 'REGULAR_MODE', source_mode, 'REGULAR_FLAG_MODE', 'WRAP', port)
    context.response = cp_mset.sendMessageGetResponse('SetCaptureCfg', config)

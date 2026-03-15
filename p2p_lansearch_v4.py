#!/usr/bin/env python3

import os, logging, socket, re, struct, time
from netifaces import interfaces, ifaddresses, AF_INET

LOG_LEVEL = logging.DEBUG if 'DEBUG' in os.environ and os.environ['DEBUG'] else logging.INFO
logging.basicConfig(format='%(message)s', level=LOG_LEVEL)

P2P_LAN_BROADCAST_IP     = '255.255.255.255'
P2P_LAN_PORT             = 32108
P2P_MAGIC_NUM            = 0xF1
P2P_HEADER_SIZE          = 4
MSG_LAN_SEARCH           = 0x30
MSG_LAN_SEARCH_EXT       = 0x32
MSG_PUNCH_PKT            = 0x41
MSG_PUNCH_TO             = 0x42  # reply punch to establish session
MSG_ALIVE                = 0xE0  # keepalive
MSG_ALIVE_ACK            = 0xE1  # keepalive ack
MSG_DRW                  = 0xD0  # data channel (carries auth + commands)
MSG_DRW_ACK              = 0xD1  # ack for DRW
MSG_CLOSE                = 0xF0  # close session

# Inner (DRW payload) command types used by most CS2/YsxLite cameras
IPCAM_CMD_LOGIN_REQ      = 0x00  # login request inside DRW
IPCAM_CMD_LOGIN_ACK      = 0x01  # login response

YUNNI_CHECK_CODE_PATTERN = re.compile('[A-F]{5}')
VSTARCAM_PREFIXES        = ['VSTD', 'VSTF', 'QHSV', 'EEEE', 'ROSS', 'ISRP', 'GCMN', 'ELSA']

DEFAULT_PASSWORDS = ['000000', '123456', '888888', 'admin', '']

def fetchLocalIPv4Addresses():
    ret = []
    ifaces = interfaces()
    for iface in ifaces:
        addrs = ifaddresses(iface)
        if AF_INET in addrs: addrs = addrs[AF_INET]
        else: continue
        for addr in addrs:
            ip = addr['addr']
            if ip in ret or ip == '0.0.0.0' or ip[0:3] == '127' or ip[0:7] == '169.254': continue
            ret.append(ip)
    return ret

class Device:
    def __init__(self, prefix, serial, checkCode):
        self.prefix    = prefix
        self.serial    = serial
        self.checkCode = checkCode
        self.isYunniDevice = prefix in VSTARCAM_PREFIXES or YUNNI_CHECK_CODE_PATTERN.match(checkCode)
        self.uid = '%s-%s-%s' % (self.prefix, str(self.serial).zfill(6), self.checkCode)
        self.ip   = None
        self.port = None

class P2PClient:
    def __init__(self):
        self.devices    = {}
        self.drw_index  = 0  # rolling packet index for DRW messages

    # ------------------------------------------------------------------ #
    #  Packet builders                                                     #
    # ------------------------------------------------------------------ #

    def createP2PMessage(self, type, payload=bytes(0)):
        """Build a standard PPPP header + payload."""
        payloadSize = len(payload)
        buff = bytearray(P2P_HEADER_SIZE + payloadSize)
        buff[0] = P2P_MAGIC_NUM
        buff[1] = type
        buff[2:4] = payloadSize.to_bytes(2, 'big')
        buff[4:] = payload
        return buff

    def createDRWMessage(self, channel, payload):
        """
        Wrap a payload inside a MSG_DRW packet.

        DRW header (inside the PPPP payload):
          Byte 0:   magic    = 0x01
          Byte 1:   channel  (0-7)
          Byte 2-3: index    (big-endian, rolling counter)
          Byte 4+:  inner payload
        """
        drw_header = bytearray(4)
        drw_header[0] = 0x01               # DRW magic
        drw_header[1] = channel & 0x07
        drw_header[2:4] = self.drw_index.to_bytes(2, 'big')
        self.drw_index = (self.drw_index + 1) & 0xFFFF

        drw_payload = bytes(drw_header) + bytes(payload)
        return self.createP2PMessage(MSG_DRW, drw_payload)

    def createLoginPayload(self, username, password):
        """
        Alternative CS2 format - simpler, no inner magic header.
        Some YsxLite cameras use this stripped-down format.
    
        Structure:
          Bytes  0-31: username (null-padded, 32 bytes)
          Bytes 32-63: password (null-padded, 32 bytes)
        """
        USERNAME_LEN = 32
        PASSWORD_LEN = 32

        body  = username.encode('utf-8').ljust(USERNAME_LEN, b'\x00')[:USERNAME_LEN]
        body += password.encode('utf-8').ljust(PASSWORD_LEN, b'\x00')[:PASSWORD_LEN]
        return body

    # ------------------------------------------------------------------ #
    #  LAN search (unchanged from original)                               #
    # ------------------------------------------------------------------ #

    def tryLANSearch(self, sourceIp):
        logging.debug('Starting LAN search from IP: %s' % sourceIp)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.settimeout(.5)
        s.bind((sourceIp, 0))

        s.sendto(self.createP2PMessage(MSG_LAN_SEARCH),     (P2P_LAN_BROADCAST_IP, P2P_LAN_PORT))
        s.sendto(self.createP2PMessage(MSG_LAN_SEARCH_EXT), (P2P_LAN_BROADCAST_IP, P2P_LAN_PORT))

        while True:
            try:
                (buff, rinfo) = s.recvfrom(1024)
                logging.debug('Data from %s: %s' % (rinfo, buff.hex()))
                try:
                    device = self.parsePunchPkt(buff)
                except Exception as e:
                    logging.error('Failed to parse P2P message (%s): %s' % (e, buff.hex()))
                    continue

                if device.uid in self.devices:
                    continue

                device.ip   = rinfo[0]
                device.port = rinfo[1]
                self.devices[device.uid] = device

                judgement = ('CS2 Network P2P or iLnkP2P' if device.prefix == 'EEEE'
                             else ('iLnkP2P' if device.isYunniDevice else 'CS2 Network P2P'))

                logging.info('===================================================\n'
                             '[*] Found %s device %s at %s\n'
                             '===================================================\n'
                             % (judgement, device.uid, device.ip))
            except socket.timeout:
                return

    def parsePunchPkt(self, buff):
        if len(buff) < 4 or buff[0] != P2P_MAGIC_NUM:
            raise Exception('Invalid P2P message')
        if buff[1] != MSG_PUNCH_PKT:
            raise Exception('Unexpected P2P message type: 0x%02x' % buff[1])

        prefix    = buff[4:12].decode('ascii').rstrip('\0')
        serial    = int.from_bytes(buff[12:16], 'big')
        checkCode = buff[16:22].decode('ascii').rstrip('\0')
        return Device(prefix, serial, checkCode)

    # ------------------------------------------------------------------ #
    #  Auth session                                                        #
    # ------------------------------------------------------------------ #

    def tryAuth(self, device, username='admin', passwords=None):
        """
        For CS2 LAN devices the MSG_PUNCH_PKT received during discovery
            already opens the session. Skip MSG_PUNCH_TO and send login directly.
        """
        if passwords is None:
            passwords = DEFAULT_PASSWORDS

        logging.info('[*] Attempting auth with device %s at %s:%d'
                     % (device.uid, device.ip, P2P_LAN_PORT))

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        camera_addr = (device.ip, P2P_LAN_PORT)

        # ---- Step 1: Re-send LAN search to re-open session ----
        # The punch PKT reply from discovery is the session opener.
        # We re-trigger it here so this method is self-contained.
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        lan_search = self.createP2PMessage(MSG_LAN_SEARCH)
        s.sendto(lan_search, (P2P_LAN_BROADCAST_IP, P2P_LAN_PORT))
        logging.debug('[>] Sent MSG_LAN_SEARCH to re-establish session')

        # ---- Step 2: Wait for PUNCH_PKT (session established) ----
        try:
            data, addr = s.recvfrom(1024)
            logging.debug('[<] Punch response: %s from %s' % (data.hex(), addr))

            if data[0] == P2P_MAGIC_NUM and data[1] == MSG_PUNCH_PKT:
                # Camera may reply from same or different port
                camera_addr = (device.ip, addr[1])
                logging.info('[*] Session established, camera responding on port %d' % addr[1])
            else:
               logging.warning('[!] Unexpected response type: 0x%02x' % data[1])

        except socket.timeout:
            logging.warning('[!] No punch response. Trying auth anyway on port 32108...')

        # Disable broadcast for subsequent unicast packets
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 0)

        # ---- Step 3: Try each password ----
        for password in passwords:
            logging.info('[*] Trying credentials: %s / %s' % (username, password or '(blank)'))

            login_payload = self.createLoginPayload(username, password)
            drw_pkt = self.createDRWMessage(channel=0, payload=login_payload)
            s.sendto(drw_pkt, camera_addr)
            logging.debug('[>] Sent MSG_DRW login (%d bytes): %s' % (len(drw_pkt), drw_pkt.hex()))

            # Camera may send a DRW_ACK first, then the actual login response
            for attempt in range(3):  # read up to 3 packets
                try:
                    data, addr = s.recvfrom(4096)
                    logging.debug('[<] Response #%d (%d bytes): %s' % (attempt, len(data), data.hex()))

                    if data[1] == MSG_DRW_ACK:
                        logging.debug('[<] Got MSG_DRW_ACK, waiting for login response...')
                        continue  # read next packet

                    result = self.parseLoginResponse(data)
                    if result is None:
                        logging.debug('[!] Unparseable response, raw: %s' % data.hex())
                        continue

                    if result == 0:
                        logging.info('[+] AUTH SUCCESS with password: "%s"' % password)
                        self.keepAlive(s, camera_addr)
                        s.close()
                        return True
                    else:
                        logging.warning('[-] Auth failed (code: %d) for password "%s"' % (result, password))
                    break

                except socket.timeout:
                    logging.warning('[!] Timeout waiting for login response (attempt %d)' % attempt)
                    break

            # # Try raw login message types used by some CS2 variants
            # for msg_type in [0x67, 0x10, 0x1A]:
            #     raw_login = self.createP2PMessage(msg_type, 
            #                 username.encode().ljust(32,b'\x00') + 
            #                 password.encode().ljust(32,b'\x00'))
            #     s.sendto(raw_login, camera_addr)
            #     logging.debug('[>] Trying raw login type 0x%02x' % msg_type)
            #     try:
            #         data, _ = s.recvfrom(4096)
            #         logging.debug('[<] Got response to 0x%02x: %s' % (msg_type, data.hex()))
            #     except socket.timeout:
            #         logging.debug('[!] No response to type 0x%02x' % msg_type)

        logging.error('[x] All passwords failed.')

        s.close()
        return False

    def parseLoginResponse(self, data):
        """
        Parse a DRW login ACK response.
        Returns 0 on success, non-zero error code on failure, None if unparseable.

        Expected structure:
          PPPP header (4 bytes)
          DRW header  (4 bytes): magic, channel, index[2]
          Inner header (8 bytes): magic[4], cmd, reserved, length[2]
          Result code (4 bytes, little-endian uint32): 0 = success
        """
        MIN_LEN = 4 + 4 + 8 + 4
        if len(data) < MIN_LEN:
            logging.debug('Response too short: %d bytes' % len(data))
            return None

        if data[0] != P2P_MAGIC_NUM:
            logging.debug('Not a PPPP packet')
            return None

        msg_type = data[1]
        logging.debug('Response message type: 0x%02x' % msg_type)

        # Handle DRW ACK (0xD1) — the camera may ack first
        if msg_type == MSG_DRW_ACK:
            logging.debug('[<] Received MSG_DRW_ACK (acknowledgement only)')
            return None  # not a login response, need to read next packet

        if msg_type != MSG_DRW:
            logging.debug('Not a DRW message, skipping')
            return None

        # Skip PPPP header (4) + DRW header (4) = offset 8
        offset = 8

        # Inner magic should be 0x5A5A5A5A
        inner_magic = int.from_bytes(data[offset:offset+4], 'big')
        if inner_magic != 0x5A5A5A5A:
            logging.debug('Unexpected inner magic: 0x%08x' % inner_magic)
            return None

        cmd_type = data[offset + 4]
        logging.debug('Inner command type: 0x%02x' % cmd_type)

        if cmd_type != IPCAM_CMD_LOGIN_ACK:
            logging.debug('Not a login ACK command')
            return None

        # Result code at offset 8 (inner header) + 8 (inner header size) = 16
        result_offset = offset + 8
        if len(data) < result_offset + 4:
            return None

        result_code = int.from_bytes(data[result_offset:result_offset+4], 'little')
        logging.debug('Login result code: %d' % result_code)
        return result_code

    def keepAlive(self, sock, camera_addr, count=3):
        """Send a few keepalive pings to maintain the session."""
        logging.info('[*] Sending keepalive packets...')
        for i in range(count):
            alive = self.createP2PMessage(MSG_ALIVE)
            sock.sendto(alive, camera_addr)
            logging.debug('[>] Sent MSG_ALIVE #%d' % i)
            try:
                data, _ = sock.recvfrom(1024)
                if data[1] == MSG_ALIVE_ACK:
                    logging.debug('[<] Got MSG_ALIVE_ACK #%d' % i)
            except socket.timeout:
                logging.debug('[!] No ALIVE_ACK #%d' % i)
            time.sleep(0.5)


def main():
    logging.info('[*] P2P LAN Search + Auth v2.0\n'
                 '[*] Searching for P2P devices...\n')
    client = P2PClient()
    ips = fetchLocalIPv4Addresses()

    for ip in ips:
        try:
            client.tryLANSearch(ip)
        except Exception as e:
            logging.error('LAN search failed on adapter %s: %s' % (ip, e))

    if not client.devices:
        logging.info('[*] No devices found.')
        return

    logging.info('[*] Done searching. Found %d device(s).\n' % len(client.devices))

    # Attempt auth on each discovered device
    for uid, device in client.devices.items():
        client.tryAuth(device, username='admin', passwords=DEFAULT_PASSWORDS)

    logging.info('[*] Auth attempts complete.')

if __name__ == '__main__':
    main()

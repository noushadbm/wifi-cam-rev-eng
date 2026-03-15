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
MSG_PUNCH_TO             = 0x42
MSG_ALIVE                = 0xE0
MSG_ALIVE_ACK            = 0xE1
MSG_DRW                  = 0xD0
MSG_DRW_ACK              = 0xD1
MSG_CLOSE                = 0xF0

YUNNI_CHECK_CODE_PATTERN = re.compile('[A-F]{5}')
VSTARCAM_PREFIXES        = ['VSTD', 'VSTF', 'QHSV', 'EEEE', 'ROSS', 'ISRP', 'GCMN', 'ELSA']

# Try your known password first, then common defaults
DEFAULT_PASSWORDS = ['WuZfSZHC', '000000', '123456', '888888', 'admin', '']

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
        self.uid  = '%s-%s-%s' % (self.prefix, str(self.serial).zfill(6), self.checkCode)
        self.ip   = None
        self.port = P2P_LAN_PORT

class P2PClient:
    def __init__(self):
        self.devices   = {}
        self.drw_index = 0

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
        Build a MSG_DRW packet.
        Reverse-engineered from YsxLite capture:
          Byte 0:   0xD1        (DRW marker — NOT 0x01 as commonly documented)
          Byte 1:   channel
          Bytes 2-3: index      (big-endian rolling counter)
          Bytes 4+: payload
        """
        drw_header = bytearray(4)
        drw_header[0] = 0xD1
        drw_header[1] = channel & 0x07
        drw_header[2:4] = self.drw_index.to_bytes(2, 'big')
        self.drw_index = (self.drw_index + 1) & 0xFFFF

        return self.createP2PMessage(MSG_DRW, bytes(drw_header) + bytes(payload))

    def createLoginPayload(self, username, password):
        """
        Login payload format reverse-engineered from YsxLite app capture.

        Full DRW payload is 176 bytes:
          Bytes  0-9:   inner header  (10 bytes, fixed magic)
          Bytes 10-29:  username      (20 bytes, null-padded)
          Bytes 30-49:  password      (20 bytes, null-padded)
          Bytes 50-175: padding zeros (126 bytes)
        """
        USERNAME_LEN = 20
        PASSWORD_LEN = 20
        TOTAL_LEN    = 172

        inner_header = bytes([
            0x01, 0x0a, 0x20, 0x10,   # command magic
            0xa4, 0x00, 0xff, 0x00,   # flags
            0x00, 0x00                # padding
        ])

        body  = username.encode('utf-8').ljust(USERNAME_LEN, b'\x00')[:USERNAME_LEN]
        body += password.encode('utf-8').ljust(PASSWORD_LEN, b'\x00')[:PASSWORD_LEN]

        payload = inner_header + body
        # Pad to TOTAL_LEN
        payload += b'\x00' * (TOTAL_LEN - len(payload))

        return payload

    def parseLoginResponse(self, data):
        """
        Parse camera login ACK response.
        Captured format:
          f1 d1 00 06   PPPP header: type=0xD1 (DRW_ACK), length=6
          d2 00 00 01   DRW response header
          XX XX         result code (big-endian, 0x0000 = success)

        Returns 0 on success, non-zero on failure, None if unparseable.
        """
        if len(data) < 10 or data[0] != P2P_MAGIC_NUM:
            logging.debug('Too short or bad magic: %s' % data.hex())
            return None

        msg_type = data[1]
        logging.debug('Response type: 0x%02x' % msg_type)

        if msg_type == MSG_DRW:
            # Could be a data packet before the ACK — log and ignore
            logging.debug('Got MSG_DRW (not ACK), raw: %s' % data.hex())
            return None

        if msg_type != MSG_DRW_ACK:
            logging.debug('Not a DRW_ACK (0x%02x), skipping' % msg_type)
            return None

        # Result code at bytes 8-9
        result = int.from_bytes(data[8:10], 'big')
        logging.debug('Login result code: 0x%04x' % result)
        return result

    # ------------------------------------------------------------------ #
    #  LAN Search                                                          #
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
    #  Auth                                                                #
    # ------------------------------------------------------------------ #

    def tryAuth(self, device, username='admin', passwords=None):
        if passwords is None:
            passwords = DEFAULT_PASSWORDS

        logging.info('[*] Attempting auth with %s at %s:%d'
                    % (device.uid, device.port, device.port))

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.settimeout(2)
        camera_addr = (device.ip, device.port)

        # ---- Step 1: Send LAN search to get punch reply ----
        s.sendto(self.createP2PMessage(MSG_LAN_SEARCH), (P2P_LAN_BROADCAST_IP, P2P_LAN_PORT))
        logging.debug('[>] Sent MSG_LAN_SEARCH')

        try:
            data, addr = s.recvfrom(1024)
            logging.debug('[<] Punch reply: %s from %s' % (data.hex(), addr))
            camera_addr = (device.ip, addr[1])
            logging.info('[*] Camera on port %d' % addr[1])
        except socket.timeout:
            logging.warning('[!] No punch reply, continuing anyway...')

        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 0)

        # ---- Step 2: Send MSG_PUNCH_TO (0x42) with UID back to camera ----
        punch_payload = bytearray(20)
        prefix_bytes = device.prefix.encode('ascii').ljust(8, b'\x00')[:8]
        punch_payload[0:8]   = prefix_bytes
        punch_payload[8:12]  = device.serial.to_bytes(4, 'big')
        checkcode_bytes = device.checkCode.encode('ascii').ljust(8, b'\x00')[:8]
        punch_payload[12:20] = checkcode_bytes[:8]

        punch_to = self.createP2PMessage(MSG_PUNCH_TO, bytes(punch_payload))
        s.sendto(punch_to, camera_addr)
        logging.debug('[>] Sent MSG_PUNCH_TO with UID: %s' % punch_to.hex())

        # ---- Step 3: Send MSG_ALIVE and handle camera's ALIVE burst ----
        s.sendto(self.createP2PMessage(MSG_ALIVE), camera_addr)
        logging.debug('[>] Sent MSG_ALIVE')

        # Drain camera's ALIVE responses and reply with ALIVE_ACK
        deadline = time.time() + 2.0
        while time.time() < deadline:
            try:
                data, addr = s.recvfrom(1024)
                logging.debug('[<] Handshake packet 0x%02x: %s' % (data[1], data.hex()))

                if data[1] == MSG_ALIVE:
                    ack = self.createP2PMessage(MSG_ALIVE_ACK)
                    s.sendto(ack, camera_addr)
                    logging.debug('[>] Sent MSG_ALIVE_ACK')

                elif data[1] == MSG_PUNCH_PKT:
                    # Camera re-sending punch, just acknowledge
                    punch_ack = self.createP2PMessage(MSG_PUNCH_TO, bytes(punch_payload))
                    s.sendto(punch_ack, camera_addr)
                    logging.debug('[>] Re-sent MSG_PUNCH_TO')

            except socket.timeout:
                break

        # ---- Step 4: Try each password ----
        for password in passwords:
            logging.info('[*] Trying: %s / %s' % (username, password or '(blank)'))

            login_payload = self.createLoginPayload(username, password)
            drw_pkt = self.createDRWMessage(channel=0, payload=login_payload)
            s.sendto(drw_pkt, camera_addr)
            logging.debug('[>] Sent login DRW (%d bytes): %s' % (len(drw_pkt), drw_pkt.hex()))

            for attempt in range(5):
                try:
                    data, addr = s.recvfrom(4096)
                    logging.debug('[<] Response #%d (%d bytes): %s'
                                % (attempt, len(data), data.hex()))

                    # Handle interleaved ALIVE requests
                    if data[1] == MSG_ALIVE:
                        s.sendto(self.createP2PMessage(MSG_ALIVE_ACK), camera_addr)
                        logging.debug('[>] Sent MSG_ALIVE_ACK (interleaved)')
                        continue

                    result = self.parseLoginResponse(data)
                    if result is None:
                        continue

                    if result == 0:
                        logging.info('[+] AUTH SUCCESS! password="%s"' % password)
                        self.keepAlive(s, camera_addr)
                        s.close()
                        return True
                    else:
                        logging.warning('[-] Auth failed (code: 0x%04x) for "%s"'
                                        % (result, password))
                        break

                except socket.timeout:
                    logging.debug('[!] Timeout attempt %d for "%s"' % (attempt, password))
                    break

        logging.error('[x] All passwords exhausted.')
        s.close()
        return False

    # def tryAuth(self, device, username='admin', passwords=None):
    #     """
    #     Authenticate with camera over LAN.

    #     Correct flow (from capture analysis):
    #       1. Re-send MSG_LAN_SEARCH → camera replies with MSG_PUNCH_PKT (session open)
    #       2. Send MSG_DRW with login payload
    #       3. Camera replies MSG_DRW_ACK with result code 0x0000 = success
    #       4. Send MSG_ALIVE keepalives to hold session
    #     """
    #     if passwords is None:
    #         passwords = DEFAULT_PASSWORDS

    #     logging.info('[*] Attempting auth with %s at %s:%d'
    #                  % (device.uid, device.ip, device.port))

    #     s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #     s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    #     s.settimeout(2)

    #     camera_addr = (device.ip, device.port)

    #     # ---- Step 1: Re-trigger LAN search to open session ----
    #     lan_search = self.createP2PMessage(MSG_LAN_SEARCH)
    #     s.sendto(lan_search, (P2P_LAN_BROADCAST_IP, P2P_LAN_PORT))
    #     logging.debug('[>] Sent MSG_LAN_SEARCH (session open)')

    #     try:
    #         data, addr = s.recvfrom(1024)
    #         logging.debug('[<] Punch response: %s from %s' % (data.hex(), addr))

    #         if data[0] == P2P_MAGIC_NUM and data[1] == MSG_PUNCH_PKT:
    #             camera_addr = (device.ip, addr[1])
    #             logging.info('[*] Session open, camera port: %d' % addr[1])
    #         else:
    #             logging.warning('[!] Unexpected response: 0x%02x, trying anyway...' % data[1])

    #     except socket.timeout:
    #         logging.warning('[!] No punch reply, trying auth anyway on port %d...' % device.port)

    #     # Disable broadcast for unicast auth packets
    #     s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 0)

    #     # ---- Step 2: Try each password ----
    #     for password in passwords:
    #         logging.info('[*] Trying: %s / %s' % (username, password or '(blank)'))

    #         login_payload = self.createLoginPayload(username, password)
    #         drw_pkt = self.createDRWMessage(channel=0, payload=login_payload)
    #         s.sendto(drw_pkt, camera_addr)
    #         logging.debug('[>] Sent login DRW (%d bytes): %s' % (len(drw_pkt), drw_pkt.hex()))

    #         # Camera may send multiple packets — read up to 5
    #         for attempt in range(5):
    #             try:
    #                 data, addr = s.recvfrom(4096)
    #                 logging.debug('[<] Response #%d (%d bytes): %s' % (attempt, len(data), data.hex()))

    #                 result = self.parseLoginResponse(data)

    #                 if result is None:
    #                     continue  # not a login ACK, read next packet

    #                 if result == 0:
    #                     logging.info('[+] AUTH SUCCESS! password="%s"' % password)
    #                     self.keepAlive(s, camera_addr)
    #                     s.close()
    #                     return True
    #                 else:
    #                     logging.warning('[-] Auth failed (code: 0x%04x) for "%s"' % (result, password))
    #                     break

    #             except socket.timeout:
    #                 logging.debug('[!] Timeout on attempt %d for password "%s"' % (attempt, password))
    #                 break

    #     logging.error('[x] All passwords exhausted.')
    #     s.close()
    #     return False

    def keepAlive(self, sock, camera_addr, count=3):
        """
        Send keepalive pings to maintain session.
        Captured alive packet: f1e0 0000 (4 bytes, zero payload)
        Camera replies:        f1e1 0000 (4 bytes)
        """
        logging.info('[*] Sending keepalives...')
        for i in range(count):
            alive = self.createP2PMessage(MSG_ALIVE)
            sock.sendto(alive, camera_addr)
            logging.debug('[>] Sent MSG_ALIVE #%d' % i)
            try:
                data, _ = sock.recvfrom(1024)
                if data[1] == MSG_ALIVE_ACK:
                    logging.info('[<] Got MSG_ALIVE_ACK #%d — session alive!' % i)
                else:
                    logging.debug('[<] Unexpected response to ALIVE: 0x%02x' % data[1])
            except socket.timeout:
                logging.debug('[!] No ALIVE_ACK #%d' % i)
            time.sleep(0.5)


def main():
    logging.info('[*] P2P LAN Search + Auth v4.0\n'
                 '[*] Searching for P2P devices...\n')
    client = P2PClient()
    ips = fetchLocalIPv4Addresses()

    for ip in ips:
        try:
            client.tryLANSearch(ip)
        except Exception as e:
            logging.error('LAN search failed on %s: %s' % (ip, e))

    if not client.devices:
        logging.info('[*] No devices found.')
        return

    logging.info('[*] Found %d device(s).\n' % len(client.devices))

    for uid, device in client.devices.items():
        client.tryAuth(device, username='admin', passwords=DEFAULT_PASSWORDS)

    logging.info('[*] Done.')

if __name__ == '__main__':
    main()

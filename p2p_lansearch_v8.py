#!/usr/bin/env python3

import os, logging, socket, re, struct, time, threading
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

# Inner DRW command types (byte 2 of inner header)
CMD_LOGIN_REQ            = 0x10   # 01 0a 20 10
CMD_CAM_INFO             = 0x11   # 01 0a 08 11  (camera sends this after login)
CMD_VIDEO_REQ            = 0x10   # 01 0a 08 10  (we send this to start video)

YUNNI_CHECK_CODE_PATTERN = re.compile('[A-F]{5}')
VSTARCAM_PREFIXES        = ['VSTD', 'VSTF', 'QHSV', 'EEEE', 'ROSS', 'ISRP', 'GCMN', 'ELSA']

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
        self._stop     = False

    # ------------------------------------------------------------------ #
    #  Packet builders                                                     #
    # ------------------------------------------------------------------ #

    def createP2PMessage(self, type, payload=bytes(0)):
        payloadSize = len(payload)
        buff = bytearray(P2P_HEADER_SIZE + payloadSize)
        buff[0] = P2P_MAGIC_NUM
        buff[1] = type
        buff[2:4] = payloadSize.to_bytes(2, 'big')
        buff[4:] = payload
        return buff

    def createDRWMessage(self, channel, payload):
        drw_header = bytearray(4)
        drw_header[0] = 0xD1
        drw_header[1] = channel & 0x07
        drw_header[2:4] = self.drw_index.to_bytes(2, 'big')
        self.drw_index = (self.drw_index + 1) & 0xFFFF
        return self.createP2PMessage(MSG_DRW, bytes(drw_header) + bytes(payload))

    def createLoginPayload(self, username, password):
        USERNAME_LEN = 20
        PASSWORD_LEN = 20
        TOTAL_LEN    = 172

        inner_header = bytes([
            0x01, 0x0a, 0x20, 0x10,
            0xa4, 0x00, 0xff, 0x00,
            0x00, 0x00
        ])
        body  = username.encode('utf-8').ljust(USERNAME_LEN, b'\x00')[:USERNAME_LEN]
        body += password.encode('utf-8').ljust(PASSWORD_LEN, b'\x00')[:PASSWORD_LEN]
        payload = inner_header + body
        payload += b'\x00' * (TOTAL_LEN - len(payload))
        return payload

    def createVideoRequestPayload(self, token):
        """
        Video request mirrors the camera info packet structure.
        Use 01 0a 20 10 (same family as login 01 0a 20 10).
        Token extracted from camera's info packet echoed back.
        """
        payload = bytes([0x01, 0x0a, 0x20, 0x10,
                        0x04, 0x00, 0xff, 0x00])
        payload += token
        return payload

    def extractTokenFromCamInfo(self, data):
        """
        Camera info packet (20 bytes total):
            f1 d0 00 10   PPPP header      (4 bytes)
            d1 00 00 00   DRW header       (4 bytes)
            01 0a 20 11   inner cmd        (4 bytes)
            04 00 ff 00   flags            (4 bytes)
            XX XX XX XX   token            (4 bytes)  ← offset 16
        """
        if len(data) < 20 or data[0] != P2P_MAGIC_NUM or data[1] != MSG_DRW:
            return None

        # Inner cmd byte at offset 10 — accept both 0x11 variants
        inner_cmd_byte = data[10]
        logging.debug('Inner cmd byte: 0x%02x' % inner_cmd_byte)

        if inner_cmd_byte not in [0x11, 0x20]:
            return None

        token = bytes(data[16:20])
        logging.debug('Token: %s' % token.hex())
        return token

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
                    logging.error('Failed to parse (%s): %s' % (e, buff.hex()))
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
            raise Exception('Unexpected type: 0x%02x' % buff[1])
        prefix    = buff[4:12].decode('ascii').rstrip('\0')
        serial    = int.from_bytes(buff[12:16], 'big')
        checkCode = buff[16:22].decode('ascii').rstrip('\0')
        return Device(prefix, serial, checkCode)

    # ------------------------------------------------------------------ #
    #  Handshake + Auth                                                    #
    # ------------------------------------------------------------------ #

    def doHandshakeAndAuth(self, s, device, username, password):
        """
        Full handshake and login sequence.
        Returns camera_addr tuple on success, None on failure.
        """
        camera_addr = (device.ip, device.port)

        # Step 1: LAN search → get punch reply
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(self.createP2PMessage(MSG_LAN_SEARCH), (P2P_LAN_BROADCAST_IP, P2P_LAN_PORT))
        logging.debug('[>] MSG_LAN_SEARCH')

        try:
            data, addr = s.recvfrom(1024)
            logging.debug('[<] Punch: %s' % data.hex())
            if data[1] == MSG_PUNCH_PKT:
                camera_addr = (device.ip, addr[1])
                logging.info('[*] Session open on port %d' % addr[1])
        except socket.timeout:
            logging.warning('[!] No punch reply, continuing...')

        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 0)

        # Step 2: Send MSG_PUNCH_TO with UID
        punch_payload = bytearray(20)
        punch_payload[0:8]   = device.prefix.encode('ascii').ljust(8, b'\x00')
        punch_payload[8:12]  = device.serial.to_bytes(4, 'big')
        punch_payload[12:20] = device.checkCode.encode('ascii').ljust(8, b'\x00')
        s.sendto(self.createP2PMessage(MSG_PUNCH_TO, bytes(punch_payload)), camera_addr)
        logging.debug('[>] MSG_PUNCH_TO with UID')

        # Step 3: ALIVE handshake
        s.sendto(self.createP2PMessage(MSG_ALIVE), camera_addr)
        logging.debug('[>] MSG_ALIVE')

        deadline = time.time() + 2.0
        while time.time() < deadline:
            try:
                data, _ = s.recvfrom(1024)
                logging.debug('[<] Handshake 0x%02x' % data[1])
                if data[1] == MSG_ALIVE:
                    s.sendto(self.createP2PMessage(MSG_ALIVE_ACK), camera_addr)
                    logging.debug('[>] MSG_ALIVE_ACK')
            except socket.timeout:
                break

        # Step 4: Login
        logging.info('[*] Sending login: %s / %s' % (username, password or '(blank)'))
        login_payload = self.createLoginPayload(username, password)
        drw_pkt = self.createDRWMessage(channel=0, payload=login_payload)
        s.sendto(drw_pkt, camera_addr)
        logging.debug('[>] Login DRW: %s' % drw_pkt.hex())

        for _ in range(10):
            try:
                data, _ = s.recvfrom(4096)
                logging.debug('[<] Login response 0x%02x (%d bytes): %s'
                              % (data[1], len(data), data.hex()))

                if data[1] == MSG_ALIVE:
                    s.sendto(self.createP2PMessage(MSG_ALIVE_ACK), camera_addr)
                    continue

                if data[1] == MSG_DRW_ACK:
                    result = int.from_bytes(data[8:10], 'big')
                    if result == 0:
                        logging.info('[+] AUTH SUCCESS!')
                        return camera_addr
                    else:
                        logging.error('[-] Auth failed code=0x%04x' % result)
                        return None

            except socket.timeout:
                break

        logging.error('[!] No login response')
        return None

    # ------------------------------------------------------------------ #
    #  Video stream                                                        #
    # ------------------------------------------------------------------ #

    def streamVideo(self, device, username='admin', password='WuZfSZHC',
                    output_file='stream.h264', duration=30):
        """
        Full flow: handshake → auth → request video → save raw H.264 to file.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)

        camera_addr = self.doHandshakeAndAuth(s, device, username, password)
        if camera_addr is None:
            s.close()
            return False

        # Step 5: Wait for camera info packet (0xD0 with inner cmd 0x11)
        # Camera sends this right after login ACK
        token = None
        logging.info('[*] Waiting for camera info packet...')

        deadline = time.time() + 3.0
        while time.time() < deadline:
            try:
                data, _ = s.recvfrom(4096)
                logging.debug('[<] Post-login 0x%02x (%d bytes): %s'
                              % (data[1], len(data), data.hex()))

                if data[1] == MSG_ALIVE:
                    s.sendto(self.createP2PMessage(MSG_ALIVE_ACK), camera_addr)
                    logging.debug('[>] MSG_ALIVE_ACK')
                    continue

                if data[1] == MSG_DRW:
                    token = self.extractTokenFromCamInfo(data)
                    if token:
                        logging.info('[*] Got token: %s' % token.hex())
                        break
                    else:
                        logging.debug('[*] DRW but no token, raw: %s' % data.hex())

            except socket.timeout:
                break

        if token is None:
            logging.warning('[!] No token received — trying with zero token')
            token = b'\x00\x00\x00\x00'

        # Step 6: Send video stream request
        video_req = self.createDRWMessage(channel=0,
                        payload=self.createVideoRequestPayload(token))
        s.sendto(video_req, camera_addr)
        logging.info('[>] Sent video stream request: %s' % video_req.hex())

        # Step 7: Receive video stream and save to file
        logging.info('[*] Receiving video stream → %s (for %ds)...' % (output_file, duration))
        logging.info('[*] Press Ctrl+C to stop early\n')

        h264_frames   = 0
        bytes_written  = 0
        start_time     = time.time()
        last_alive     = time.time()

        with open(output_file, 'wb') as f:
            while time.time() - start_time < duration:
                # Send keepalive every second
                if time.time() - last_alive > 1.0:
                    s.sendto(self.createP2PMessage(MSG_ALIVE), camera_addr)
                    last_alive = time.time()

                try:
                    data, _ = s.recvfrom(65535)

                    if data[1] == MSG_ALIVE:
                        s.sendto(self.createP2PMessage(MSG_ALIVE_ACK), camera_addr)
                        continue

                    if data[1] == MSG_DRW_ACK:
                        logging.debug('[<] DRW_ACK')
                        continue

                    if data[1] == MSG_DRW:
                        # DRW payload starts at byte 4 (pppp header)
                        # DRW sub-header is 4 bytes, so video data starts at byte 8
                        # Video packets have inner cmd 0x00 or raw H.264 NAL units
                        drw_payload = data[8:]  # skip PPPP(4) + DRW header(4)

                        # Check if this looks like H.264 NAL unit
                        # H.264 NAL start codes: 00 00 00 01 or 00 00 01
                        if (len(drw_payload) > 4 and
                            (drw_payload[0:4] == b'\x00\x00\x00\x01' or
                             drw_payload[0:3] == b'\x00\x00\x01')):
                            f.write(drw_payload)
                            f.flush()
                            h264_frames += 1
                            bytes_written += len(drw_payload)
                            if h264_frames % 30 == 0:
                                elapsed = time.time() - start_time
                                logging.info('[*] %d frames, %d bytes, %.1fs elapsed'
                                             % (h264_frames, bytes_written, elapsed))
                        else:
                            # Not raw H.264 — dump first 32 bytes for analysis
                            logging.debug('[<] DRW data (not H264?): %s'
                                          % drw_payload[:32].hex())
                            # Write it anyway — we can analyze the file later
                            f.write(drw_payload)
                            f.flush()
                            bytes_written += len(drw_payload)

                except socket.timeout:
                    logging.debug('[.] timeout, waiting for video...')
                    continue
                except KeyboardInterrupt:
                    logging.info('\n[*] Stopped by user')
                    break

        logging.info('[*] Stream saved: %d bytes, %d H.264 frames → %s'
                     % (bytes_written, h264_frames, output_file))
        logging.info('[*] Play with: ffplay %s' % output_file)
        logging.info('[*]        or: vlc %s' % output_file)

        s.close()
        return bytes_written > 0


def main():
    logging.info('[*] P2P Camera Stream v1.0\n'
                 '[*] Searching for devices...\n')
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
        client.streamVideo(
            device,
            username='admin',
            password='WuZfSZHC',
            output_file='stream.h264',
            duration=30          # record for 30 seconds
        )

if __name__ == '__main__':
    main()


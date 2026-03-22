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
            0x11, 0x0a, 0x20, 0x10,   # ← 0x11 not 0x01
            0xa4, 0x00, 0xff, 0x00,
            0x00, 0x00
        ])
        body  = username.encode('utf-8').ljust(USERNAME_LEN, b'\x00')[:USERNAME_LEN]
        body += password.encode('utf-8').ljust(PASSWORD_LEN, b'\x00')[:PASSWORD_LEN]
        payload = inner_header + body
        payload += b'\x00' * (TOTAL_LEN - len(payload))
        return payload

    def createConnectUserPayload(self, ticket):
        """
        Try both XOR'd and raw ticket — our camera may differ from cam-reverse.
        cam-reverse XORs with 0x01, but our camera's ticket 0efcffff may be used raw.
        """
        # XOR ticket with 0x01 as cam-reverse does
        xor_ticket = bytes([b ^ 0x01 for b in ticket])

        payload = bytes([0x11, 0x0a, 0x18, 0x30,  # cmd ConnectUser
                        0x0c, 0x00, 0x00, 0x00])  # flags
        payload += xor_ticket
        payload += bytes([0x03, 0x01, 0x01, 0x01,
                        0x00, 0x01, 0x01, 0x01])
        return payload

    def createStreamStartPayload(self, ticket):
        xor_ticket = bytes([b ^ 0x01 for b in ticket])
        payload = bytes([0x11, 0x0a, 0x10, 0x30,
                        0x04, 0x00, 0x00, 0x00])
        payload += xor_ticket
        return payload

    def createVideoRequestPayload(self, token):
        """
        Video request uses the 0x08 command family (media), NOT 0x20 (info/login).
        Captured from YsxLite: 01 0a 08 10  04 00 ff 00  <token 4 bytes>
        """
        payload = bytes([0x01, 0x0a, 0x08, 0x10,   # ← 0x08 not 0x20
                        0x04, 0x00, 0xff, 0x00])
        payload += token
        return payload

    def extractTokenFromCamInfo(self, data):
        if len(data) < 20 or data[0] != P2P_MAGIC_NUM or data[1] != MSG_DRW:
            return None
        drw_payload = data[8:]          # skip PPPP(4) + DRW header(4)
        if len(drw_payload) < 12:
            return None
        # Inner cmd at index 3 of drw_payload
        if drw_payload[3] != 0x11:
            logging.debug('Not cam info (byte3=0x%02x)' % drw_payload[3])
            return None
        token = bytes(drw_payload[8:12])
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
                    output_file='stream.mjpeg', duration=30):

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)

        camera_addr = self.doHandshakeAndAuth(s, device, username, password)
        if camera_addr is None:
            s.close()
            return False

        # Step 5: Wait for ConnectUserAck
        ticket = None
        logging.info('[*] Waiting for ConnectUserAck (ticket)...')
        deadline = time.time() + 3.0
        while time.time() < deadline:
            try:
                data, _ = s.recvfrom(4096)
                logging.debug('[<] Post-login 0x%02x (%d bytes): %s'
                            % (data[1], len(data), data.hex()))

                if data[1] == MSG_ALIVE:
                    s.sendto(self.createP2PMessage(MSG_ALIVE_ACK), camera_addr)
                    continue

                if data[1] == MSG_DRW_ACK:
                    continue

                if data[1] == MSG_DRW:
                    drw_payload = data[8:]
                    logging.debug('[*] DRW payload: %s' % drw_payload.hex())

                    # Accept ANY 0x20 0x11 packet as the ticket — ignore flags byte
                    if (len(drw_payload) >= 12 and
                        drw_payload[2] == 0x20 and drw_payload[3] == 0x11):
                        ticket = bytes(drw_payload[8:12])
                        logging.info('[*] Got ticket: %s (raw, will XOR for use)'
                                    % ticket.hex())
                        break

            except socket.timeout:
                break

        if ticket is None:
            logging.error('[!] No ticket received — cannot start stream')
            s.close()
            return False

        # Step 6: Send ConnectUser (0x1830)
        connect_pkt = self.createDRWMessage(channel=0,
                        payload=self.createConnectUserPayload(ticket))
        s.sendto(connect_pkt, camera_addr)
        logging.info('[>] Sent ConnectUser: %s' % connect_pkt.hex())

        # Step 7: Send StreamStart (0x1030)
        stream_pkt = self.createDRWMessage(channel=0,
                        payload=self.createStreamStartPayload(ticket))
        s.sendto(stream_pkt, camera_addr)
        logging.info('[>] Sent StreamStart: %s' % stream_pkt.hex())

        # Step 8: Wait for ConnectUserAck (0x1831) and StreamStartAck (0x1031)
        # IMPORTANT: ACK every control DRW the camera sends
        confirmed_ticket = None
        stream_ack_received = False
        logging.info('[*] Waiting for stream ACKs...')

        deadline = time.time() + 3.0
        while time.time() < deadline:
            try:
                data, _ = s.recvfrom(4096)
                logging.debug('[<] ACK phase 0x%02x (%d bytes): %s'
                            % (data[1], len(data), data.hex()))

                if data[1] == MSG_ALIVE:
                    s.sendto(self.createP2PMessage(MSG_ALIVE_ACK), camera_addr)
                    continue

                if data[1] == MSG_DRW_ACK:
                    continue

                if data[1] == MSG_DRW:
                    drw_payload = data[8:]
                    pkt_id      = int.from_bytes(data[6:8], 'big')
                    stream_byte = data[5]
                    cmd = (drw_payload[2] << 8) | drw_payload[3]
                    token = bytes(drw_payload[8:12]) if len(drw_payload) >= 12 else b'\x00'*4

                    logging.info('[*] Camera cmd=0x%04x stream=%d token=%s'
                                % (cmd, stream_byte, token.hex()))

                    # Always ACK control DRW packets
                    if stream_byte == 0x00:
                        ack = bytearray(14)
                        ack[0] = P2P_MAGIC_NUM
                        ack[1] = MSG_DRW_ACK
                        ack[2:4] = (10).to_bytes(2, 'big')
                        ack[4] = 0xd2
                        ack[5] = 0x00   # control stream
                        ack[6:8] = (1).to_bytes(2, 'big')
                        ack[8:10] = pkt_id.to_bytes(2, 'big')
                        s.sendto(bytes(ack), camera_addr)
                        logging.debug('[>] Sent DRW_ACK for control pkt %d' % pkt_id)

                    if cmd == 0x1831:
                        confirmed_ticket = token
                        logging.info('[*] ConnectUserAck ticket: %s' % token.hex())

                    elif cmd == 0x1031:
                        stream_ack_received = True
                        logging.info('[*] StreamStartAck — video should follow!')
                        # Do NOT send another StreamStart here — just wait for video
                        break

                    # If camera sends data already (stream_byte==1), video has started
                    elif stream_byte == 0x01:
                        logging.info('[*] Video data already arriving!')
                        stream_ack_received = True
                        break

            except socket.timeout:
                break

        # Step 9: No more StreamStart — video should flow after StreamStartAck ACK
        # Just go straight to receiving
        logging.info('[*] Waiting for video data...')

        # Step 10: Receive MJPEG stream
        logging.info('[*] Receiving MJPEG stream → %s (%ds)...' % (output_file, duration))
        logging.info('[*] Press Ctrl+C to stop\n')

        FRAME_HEADER  = b'\x55\xaa\x15\xa8'
        JPEG_HEADER   = b'\xff\xd8\xff'
        frame_count   = 0
        bytes_written  = 0
        start_time    = time.time()
        last_alive    = time.time()
        current_jpeg  = bytearray()
        got_any_data  = False

        with open(output_file, 'wb') as f:
            while time.time() - start_time < duration:

                if time.time() - last_alive > 1.0:
                    s.sendto(self.createP2PMessage(MSG_ALIVE), camera_addr)
                    last_alive = time.time()

                try:
                    data, _ = s.recvfrom(65535)

                    if data[1] == MSG_ALIVE:
                        s.sendto(self.createP2PMessage(MSG_ALIVE_ACK), camera_addr)
                        continue

                    if data[1] == MSG_DRW_ACK:
                        continue

                    if data[1] == MSG_DRW:
                        stream_byte = data[5]
                        drw_payload = data[8:]
                        pkt_id      = int.from_bytes(data[6:8], 'big')

                        # Send DRW ACK back to camera
                        ack = bytearray(14)
                        ack[0] = P2P_MAGIC_NUM
                        ack[1] = MSG_DRW_ACK
                        ack[2:4] = (10).to_bytes(2, 'big')
                        ack[4] = 0xd2
                        ack[5] = stream_byte
                        ack[6:8] = (1).to_bytes(2, 'big')
                        ack[8:10] = pkt_id.to_bytes(2, 'big')
                        s.sendto(bytes(ack), camera_addr)

                        # Control packet handling in stream loop
                        if stream_byte == 0x00:
                            cmd = (drw_payload[2] << 8) | drw_payload[3]
                            logging.debug('[<] Control cmd=0x%04x: %s' % (cmd, drw_payload[:16].hex()))

                            # ACK all control packets
                            ack = bytearray(14)
                            ack[0] = P2P_MAGIC_NUM
                            ack[1] = MSG_DRW_ACK
                            ack[2:4] = (10).to_bytes(2, 'big')
                            ack[4] = 0xd2
                            ack[5] = 0x00
                            ack[6:8] = (1).to_bytes(2, 'big')
                            ack[8:10] = pkt_id.to_bytes(2, 'big')
                            s.sendto(bytes(ack), camera_addr)

                            # Do NOT resend StreamStart on 0x1031 — it creates an infinite loop
                            # Just log and continue waiting
                            if cmd == 0x1031:
                                logging.debug('[*] StreamStartAck in stream loop — video should follow')
                            continue

                        # Data packet (stream_byte == 0x01)
                        got_any_data = True
                        logging.debug('[<] Data pkt_id=%d len=%d: %s'
                                    % (pkt_id, len(drw_payload), drw_payload[:8].hex()))

                        # Framed JPEG (55 aa 15 a8 header)
                        if drw_payload[0:4] == FRAME_HEADER:
                            stream_type = drw_payload[4] if len(drw_payload) > 4 else 0
                            if stream_type == 0x03:  # JPEG frame
                                jpeg_data = drw_payload[32:]  # skip 32-byte stream header
                                if current_jpeg:
                                    f.write(bytes(current_jpeg))
                                    f.flush()
                                    frame_count += 1
                                    bytes_written += len(current_jpeg)
                                    if frame_count % 10 == 0:
                                        logging.info('[*] %d frames, %d bytes, %.1fs'
                                                    % (frame_count, bytes_written,
                                                        time.time() - start_time))
                                current_jpeg = bytearray(jpeg_data)
                            continue

                        # Unframed JPEG start (ff d8 ff)
                        if drw_payload[0:3] == JPEG_HEADER:
                            if current_jpeg:
                                f.write(bytes(current_jpeg))
                                f.flush()
                                frame_count += 1
                                bytes_written += len(current_jpeg)
                                if frame_count % 10 == 0:
                                    logging.info('[*] %d frames, %d bytes, %.1fs'
                                                % (frame_count, bytes_written,
                                                    time.time() - start_time))
                            current_jpeg = bytearray(drw_payload)
                            continue

                        # Continuation chunk
                        if current_jpeg:
                            current_jpeg += drw_payload
                        else:
                            # No frame started yet — log raw data
                            logging.debug('[<] Orphan data: %s' % drw_payload[:16].hex())

                except socket.timeout:
                    if got_any_data:
                        logging.debug('[.] timeout')
                    continue
                except KeyboardInterrupt:
                    logging.info('\n[*] Stopped by user')
                    break

            # Save last frame
            if current_jpeg:
                f.write(bytes(current_jpeg))
                frame_count += 1
                bytes_written += len(current_jpeg)

        logging.info('[*] Done: %d frames, %d bytes → %s'
                    % (frame_count, bytes_written, output_file))
        logging.info('[*] Play: ffplay -f mjpeg %s' % output_file)
        s.close()
        return frame_count > 0

    def createCapsRequestPayload(self):
        """
        Request camera capabilities/info before asking for video.
        Try the 0x08 family info request — mirrors what YsxLite likely sends
        before the camera sends its full 144-byte capabilities response.
        """
        # Try: 01 0a 08 10 with flags 80 00 ff 00 (large buffer flag)
        # vs our current 04 00 ff 00 (small buffer flag)
        return bytes([0x01, 0x0a, 0x08, 0x10,
                    0x80, 0x00, 0xff, 0x00,   # ← 0x80 flag, not 0x04
                    0x00, 0x00, 0x00, 0x00])  # zero token for initial request


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


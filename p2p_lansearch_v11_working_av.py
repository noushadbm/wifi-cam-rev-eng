#!/usr/bin/env python3

import os, logging, socket, re, struct, time
from netifaces import interfaces, ifaddresses, AF_INET

LOG_LEVEL = logging.DEBUG if 'DEBUG' in os.environ and os.environ['DEBUG'] else logging.INFO
logging.basicConfig(format='%(message)s', level=LOG_LEVEL)

P2P_LAN_BROADCAST_IP = '255.255.255.255'
P2P_LAN_PORT         = 32108
P2P_MAGIC_NUM        = 0xF1
P2P_HEADER_SIZE      = 4
MSG_LAN_SEARCH       = 0x30
MSG_LAN_SEARCH_EXT   = 0x32
MSG_PUNCH_PKT        = 0x41
MSG_PUNCH_TO         = 0x42
MSG_ALIVE            = 0xE0
MSG_ALIVE_ACK        = 0xE1
MSG_DRW              = 0xD0
MSG_DRW_ACK          = 0xD1
MSG_CLOSE            = 0xF0

# Control commands (from datatypes.ts)
CMD_CONNECT_USER      = 0x2010
CMD_CONNECT_USER_ACK  = 0x2011
CMD_START_VIDEO       = 0x1030
CMD_START_VIDEO_ACK   = 0x1031
CMD_VIDEO_PARAM_SET   = 0x1830
CMD_VIDEO_PARAM_ACK   = 0x1831
CMD_DEV_STATUS        = 0x0810
CMD_DEV_STATUS_ACK    = 0x0811

# ccDest table (from datatypes.ts)
CC_DEST = {
    CMD_CONNECT_USER: 0xff00,
    CMD_DEV_STATUS:   0x0000,
    CMD_START_VIDEO:  0x0000,
    CMD_VIDEO_PARAM_SET: 0x0000,
}

START_CMD = 0x110a

YUNNI_CHECK_CODE_PATTERN = re.compile('[A-F]{5}')
VSTARCAM_PREFIXES = ['VSTD', 'VSTF', 'QHSV', 'EEEE', 'ROSS', 'ISRP', 'GCMN', 'ELSA']

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

def u16_swap(v):
    """Swap bytes of a 16-bit value (from utils.js)."""
    return ((v & 0xff) << 8) | ((v >> 8) & 0xff)

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
        self.devices          = {}
        self.outgoingCommandId = 0
        self.ticket           = [0, 0, 0, 0]

    # ------------------------------------------------------------------ #
    #  Low-level packet builders                                           #
    # ------------------------------------------------------------------ #

    def createP2PMessage(self, type, payload=bytes(0)):
        payloadSize = len(payload)
        buff = bytearray(P2P_HEADER_SIZE + payloadSize)
        buff[0] = P2P_MAGIC_NUM
        buff[1] = type
        buff[2:4] = payloadSize.to_bytes(2, 'big')
        buff[4:] = payload
        return buff

    def makeDataReadWrite(self, command, data=None):
        """
        Build a control DRW packet — mirrors impl.ts makeDataReadWrite exactly.

        Packet layout:
          Bytes 0-1:   0xF1D0       (MSG_DRW)
          Bytes 2-3:   pkt_len-4    (payload length)
          Byte  4:     0xD1         (DRW marker)
          Byte  5:     0x00         (channel)
          Bytes 6-7:   outgoingCommandId
          Bytes 8-9:   0x110a       (START_CMD)
          Bytes 10-11: command      (e.g. 0x2010)
          Bytes 12-13: u16_swap(payload_len)
          Bytes 14-15: ccDest[command]
          Bytes 16-19: ticket (4 bytes)
          Bytes 20+:   XqBytesEnc'd data (if any)
        """
        DRW_HEADER_LEN = 0x10  # bytes 0-15
        TOKEN_LEN      = 0x4   # ticket = 4 bytes

        # XqBytesEnc: rotate each byte by 4 (simple ROL cipher)
        encoded_data = None
        if data and len(data) > 4:
            encoded_data = self.XqBytesEnc(bytearray(data), len(data), 4)

        payload_len = TOKEN_LEN + (len(encoded_data) if encoded_data else 0)
        pkt_len     = DRW_HEADER_LEN + TOKEN_LEN + (len(encoded_data) if encoded_data else 0)

        buf = bytearray(pkt_len)
        # Write MSG_DRW header (big-endian u16)
        struct.pack_into('>H', buf, 0, (P2P_MAGIC_NUM << 8) | MSG_DRW)  # 0xF1D0
        struct.pack_into('>H', buf, 2, pkt_len - 4)
        buf[4] = 0xD1
        buf[5] = 0x00  # channel
        struct.pack_into('>H', buf, 6, self.outgoingCommandId)
        struct.pack_into('>H', buf, 8, START_CMD)         # 0x110a
        struct.pack_into('>H', buf, 10, command)
        struct.pack_into('>H', buf, 12, u16_swap(payload_len))
        struct.pack_into('>H', buf, 14, CC_DEST.get(command, 0x0000))
        buf[16:20] = bytes(self.ticket)

        if encoded_data:
            buf[20:20+len(encoded_data)] = encoded_data

        self.outgoingCommandId += 1
        return bytes(buf)

    def XqBytesEnc(self, data, length, rotate):
        """
        XqBytesEnc from func_replacements.js:
        1. XOR every byte with 0x01 (odd→even, even→odd)
        2. Rotate array left by `rotate` positions
        """
        # Step 1: XOR each byte with 1
        new_buf = bytearray(length)
        for i in range(length):
            b = data[i]
            new_buf[i] = b ^ 1  # odd-subtract-1 / even-add-1 = XOR with 1

        # Step 2: Rotate left by `rotate` positions
        result = bytearray(length)
        for i in range(length - rotate):
            result[i] = new_buf[i + rotate]
        for i in range(rotate):
            result[length - rotate + i] = new_buf[i]

        return result

    def makeDrwAck(self, pkt_id, stream_byte):
        """Build a DRW ACK packet."""
        buf = bytearray(14)
        struct.pack_into('>H', buf, 0, (P2P_MAGIC_NUM << 8) | MSG_DRW_ACK)
        struct.pack_into('>H', buf, 2, 10)   # length
        buf[4] = 0xD2
        buf[5] = stream_byte
        struct.pack_into('>H', buf, 6, 1)    # ack_count=1
        struct.pack_into('>H', buf, 8, pkt_id)
        return bytes(buf)

    # ------------------------------------------------------------------ #
    #  High-level commands                                                 #
    # ------------------------------------------------------------------ #

    def SendConnectUser(self, username, password):
        """
        Login — ConnectUser 0x2010
        Payload: username(32 bytes) + password(128 bytes) = 160 bytes
        """
        buf = bytearray(0x20 + 0x80)
        buf[0:len(username)] = username.encode('utf-8')
        buf[0x20:0x20+len(password)] = password.encode('utf-8')
        return self.makeDataReadWrite(CMD_CONNECT_USER, bytes(buf))

    def SendVideoParamSet(self, resolution=2):
        """
        VideoParamSet 0x1830 — set resolution before starting video.
        resolution: 1=320x240, 2=640x480, 3=640x480, 4=640x480
        From impl.ts SendVideoResolution.
        """
        resolutions = {
            1: [0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            2: [0x1, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0],
            3: [0x1, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0],
            4: [0x1, 0x0, 0x0, 0x0, 0x4, 0x0, 0x0, 0x0],
        }
        payload = bytes(resolutions.get(resolution, resolutions[2]))
        return self.makeDataReadWrite(CMD_VIDEO_PARAM_SET, payload)

    def SendStartVideo(self):
        """StartVideo 0x1030 — begin streaming."""
        return self.makeDataReadWrite(CMD_START_VIDEO, None)

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
    #  Handshake                                                           #
    # ------------------------------------------------------------------ #

    def doHandshake(self, s, device):
        """LAN search + P2PRdy punch exchange."""
        camera_addr = (device.ip, device.port)

        # LAN search → get punch reply
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
            logging.warning('[!] No punch reply')

        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 0)

        # Send P2PRdy (MSG_PUNCH_TO) with UID
        punch_payload = bytearray(20)
        punch_payload[0:8]   = device.prefix.encode('ascii').ljust(8, b'\x00')
        punch_payload[8:12]  = device.serial.to_bytes(4, 'big')
        punch_payload[12:20] = device.checkCode.encode('ascii').ljust(8, b'\x00')
        s.sendto(self.createP2PMessage(MSG_PUNCH_TO, bytes(punch_payload)), camera_addr)
        logging.debug('[>] MSG_PUNCH_TO')

        # ALIVE handshake
        s.sendto(self.createP2PMessage(MSG_ALIVE), camera_addr)
        deadline = time.time() + 2.0
        while time.time() < deadline:
            try:
                data, _ = s.recvfrom(1024)
                if data[1] == MSG_ALIVE:
                    s.sendto(self.createP2PMessage(MSG_ALIVE_ACK), camera_addr)
            except socket.timeout:
                break

        return camera_addr

    # ------------------------------------------------------------------ #
    #  Stream                                                              #
    # ------------------------------------------------------------------ #

    def streamVideo(self, device, username='admin', password='WuZfSZHC',
                    video_file='stream.mjpeg', audio_file='stream.raw',
                    duration=30):

        self.outgoingCommandId = 0
        self.ticket = [0, 0, 0, 0]

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.05)   # ← reduce timeout to 50ms for faster ACKs

        camera_addr = self.doHandshake(s, device)

        # Login
        s.settimeout(2)
        login_pkt = self.SendConnectUser(username, password)
        s.sendto(login_pkt, camera_addr)
        logging.info('[>] Sent ConnectUser')

        logged_in = False
        deadline = time.time() + 5.0
        while time.time() < deadline:
            try:
                data, _ = s.recvfrom(4096)
                if data[1] == MSG_ALIVE:
                    s.sendto(self.createP2PMessage(MSG_ALIVE_ACK), camera_addr)
                    continue
                if data[1] == MSG_DRW_ACK:
                    continue
                if data[1] == MSG_DRW:
                    pkt_id      = int.from_bytes(data[6:8], 'big')
                    stream_byte = data[5]
                    drw_payload = data[8:]
                    cmd         = struct.unpack_from('>H', drw_payload, 2)[0]
                    s.sendto(self.makeDrwAck(pkt_id, stream_byte), camera_addr)
                    if cmd == CMD_CONNECT_USER_ACK:
                        raw_payload_len = struct.unpack_from('>H', drw_payload, 4)[0]
                        payload_len = u16_swap(raw_payload_len)
                        if len(data) >= 20 + (payload_len - 4):
                            encoded = bytearray(data[20:20 + payload_len - 4])
                            decoded = self.XqBytesDec(encoded, len(encoded), 4)
                            self.ticket = list(decoded[4:8])
                        logging.info('[+] LOGIN OK! Ticket: %s' % bytes(self.ticket).hex())
                        logged_in = True
                        break
            except socket.timeout:
                break

        if not logged_in:
            logging.error('[!] Login failed')
            s.close()
            return False

        s.settimeout(0.05)   # ← fast timeout for streaming

        # Send VideoParamSet + StartVideo
        s.sendto(self.SendVideoParamSet(resolution=2), camera_addr)
        s.sendto(self.SendStartVideo(), camera_addr)
        logging.info('[>] Sent VideoParamSet + StartVideo')

        # Stream loop
        logging.info('[*] Receiving → video=%s audio=%s (%ds)'
                    % (video_file, audio_file, duration))

        FRAME_HEADER  = b'\x55\xaa\x15\xa8'
        JPEG_HEADER   = b'\xff\xd8\xff'
        STREAM_JPEG   = 0x03
        STREAM_AUDIO  = 0x06

        frame_count   = 0
        audio_chunks  = 0
        video_bytes   = 0
        audio_bytes   = 0
        start_time    = time.time()
        last_alive    = time.time()
        last_log      = time.time()
        current_jpeg  = bytearray()
        first_audio   = None

        # Pending ACK queue — batch ACKs like the real client
        pending_acks  = []   # list of (pkt_id, stream_byte)
        last_ack_sent = time.time()

        def flush_acks():
            """Send batched DRW ACK for all pending packets."""
            if not pending_acks:
                return
            # Group by stream_byte
            by_stream = {}
            for pid, sb in pending_acks:
                by_stream.setdefault(sb, []).append(pid)
            for sb, pids in by_stream.items():
                item_count = len(pids)
                reply_len  = item_count * 2 + 4
                buf = bytearray(8 + item_count * 2)
                struct.pack_into('>H', buf, 0, (P2P_MAGIC_NUM << 8) | MSG_DRW_ACK)
                struct.pack_into('>H', buf, 2, reply_len)
                buf[4] = 0xd2
                buf[5] = sb
                struct.pack_into('>H', buf, 6, item_count)
                for i, pid in enumerate(pids):
                    struct.pack_into('>H', buf, 8 + i * 2, pid)
                s.sendto(bytes(buf), camera_addr)
            pending_acks.clear()

        with open(video_file, 'wb') as vf, open(audio_file, 'wb') as af:
            while time.time() - start_time < duration:

                # Keepalive
                now = time.time()
                if now - last_alive > 0.5:
                    s.sendto(self.createP2PMessage(MSG_ALIVE), camera_addr)
                    last_alive = now

                # Flush ACKs every 10ms (matches real client behavior)
                if now - last_ack_sent > 0.01:
                    flush_acks()
                    last_ack_sent = now

                # Progress log
                if now - last_log > 2.0:
                    logging.info('[*] video=%d frames %d bytes | audio=%d chunks %d bytes | %.1fs'
                                % (frame_count, video_bytes, audio_chunks, audio_bytes,
                                    now - start_time))
                    last_log = now

                try:
                    data, _ = s.recvfrom(65535)
                except socket.timeout:
                    continue
                except KeyboardInterrupt:
                    logging.info('\n[*] Stopped by user')
                    break

                if data[1] == MSG_ALIVE:
                    s.sendto(self.createP2PMessage(MSG_ALIVE_ACK), camera_addr)
                    continue

                if data[1] == MSG_DRW_ACK:
                    continue

                if data[1] != MSG_DRW:
                    continue

                pkt_id      = int.from_bytes(data[6:8], 'big')
                stream_byte = data[5]
                drw_payload = data[8:]

                # Queue ACK
                pending_acks.append((pkt_id, stream_byte))

                # Control packet
                if stream_byte == 0x00:
                    cmd = struct.unpack_from('>H', drw_payload, 2)[0]
                    logging.debug('[<] Control cmd=0x%04x' % cmd)
                    flush_acks()  # flush immediately on control packets
                    continue

                # Data packet
                if len(drw_payload) < 4:
                    continue

                if drw_payload[0:4] == FRAME_HEADER:
                    stream_type = drw_payload[4] if len(drw_payload) > 4 else 0

                    if stream_type == STREAM_JPEG:
                        if current_jpeg:
                            vf.write(bytes(current_jpeg))
                            vf.flush()
                            frame_count += 1
                            video_bytes += len(current_jpeg)
                        current_jpeg = bytearray(drw_payload[32:])

                    elif stream_type == STREAM_AUDIO:
                        if len(drw_payload) >= 18:
                            audio_len  = struct.unpack_from('<H', drw_payload, 16)[0]
                            audio_data = drw_payload[32:32 + audio_len]
                            if audio_data:
                                if first_audio is None:
                                    first_audio = bytes(audio_data)
                                    logging.info('[*] First audio: %d bytes hex=%s'
                                                % (len(first_audio), first_audio[:8].hex()))
                                af.write(bytes(audio_data))
                                af.flush()
                                audio_chunks += 1
                                audio_bytes  += len(audio_data)
                    else:
                        logging.debug('[<] stream_type=0x%02x ignored' % stream_type)

                elif drw_payload[0:3] == JPEG_HEADER:
                    if current_jpeg:
                        vf.write(bytes(current_jpeg))
                        vf.flush()
                        frame_count += 1
                        video_bytes += len(current_jpeg)
                    current_jpeg = bytearray(drw_payload)

                elif current_jpeg:
                    current_jpeg += drw_payload

            flush_acks()
            if current_jpeg:
                vf.write(bytes(current_jpeg))
                frame_count += 1
                video_bytes += len(current_jpeg)

        # Audio format detection
        bps = audio_bytes / max(time.time() - start_time, 1)
        logging.info('\n[*] Done: %d video frames (%d bytes) | %d audio chunks (%d bytes)'
                    % (frame_count, video_bytes, audio_chunks, audio_bytes))
        logging.info('[*] Avg audio bitrate: %.0f bytes/sec' % bps)

        if audio_chunks > 0:
            if   7500 <= bps <= 8500:
                fmt = 'mulaw'
                logging.info('[*] Detected: G.711 u-law 8000Hz')
            elif 3500 <= bps <= 4500:
                fmt = 'adpcm_ima_wav'
                logging.info('[*] Detected: ADPCM 8000Hz')
            elif 15000 <= bps <= 17000:
                fmt = 's16le'
                logging.info('[*] Detected: PCM s16le 8000Hz')
            else:
                fmt = 'mulaw'
                logging.info('[*] Unknown bitrate %.0f, defaulting to mulaw' % bps)

            logging.info('[*] Play audio:  ffplay -f %s -ar 8000 -ac 1 %s' % (fmt, audio_file))
            logging.info('[*] Play video:  ffplay -f mjpeg %s' % video_file)
            logging.info('[*] Mux A+V:     ffmpeg -f mjpeg -i %s -f %s -ar 8000 -ac 1 -i %s '
                        '-c:v copy -c:a aac output_av.mp4' % (video_file, fmt, audio_file))
        else:
            logging.info('[*] No audio received — camera may not have microphone')
            logging.info('[*] Play video:  ffplay -f mjpeg %s' % video_file)

        s.close()
        return frame_count > 0

    def XqBytesDec(self, data, length, rotate):
        """
        XqBytesDec — inverse of XqBytesEnc:
        1. XOR every byte with 0x01
        2. Rotate RIGHT by `rotate` positions (opposite of Enc)
        """
        # Step 1: XOR each byte with 1
        new_buf = bytearray(length)
        for i in range(length):
            new_buf[i] = data[i] ^ 1

        # Step 2: Rotate RIGHT by rotate positions
        result = bytearray(length)
        for i in range(rotate, length):
            result[i] = new_buf[i - rotate]
        for i in range(rotate):
            result[i] = new_buf[length - rotate + i]

        return result


def main():
    logging.info('[*] P2P Camera Stream v2.0\n'
                 '[*] Searching for devices...\n')
    client = P2PClient()
    for ip in fetchLocalIPv4Addresses():
        try:
            client.tryLANSearch(ip)
        except Exception as e:
            logging.error('LAN search failed on %s: %s' % (ip, e))

    if not client.devices:
        logging.info('[*] No devices found.')
        return

    logging.info('[*] Found %d device(s).\n' % len(client.devices))
    for uid, device in client.devices.items():
        client.streamVideo(device, username='admin', password='WuZfSZHC',
                           video_file='stream.mjpeg', audio_file='stream.raw', duration=30)

if __name__ == '__main__':
    main()
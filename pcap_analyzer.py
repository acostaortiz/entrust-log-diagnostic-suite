import collections
import csv
import datetime
import gzip
import io
import json
import os
import re
import socket
import sqlite3
import statistics
import struct
import time

DLT_NAMES = {
    0: 'NULL/Loopback',
    1: 'Ethernet (EN10MB)',
    101: 'Raw IP',
    108: 'OpenBSD Loopback',
    113: 'Linux Cooked (SLL)',
    228: 'Raw IPv4',
    229: 'Raw IPv6',
    276: 'Linux Cooked v2 (SLL2)',
}

SERVICE_PORT_LABELS = {
    22: 'SSH',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    88: 'Kerberos',
    123: 'NTP',
    389: 'LDAP',
    443: 'HTTPS',
    514: 'Syslog',
    587: 'SMTP-TLS',
    636: 'LDAPS',
    1521: 'Oracle DB',
    1522: 'Oracle DB',
    1645: 'RADIUS',
    1812: 'RADIUS-Auth',
    1813: 'RADIUS-Acct',
    2483: 'Oracle TCPS',
    2484: 'Oracle TCPS',
    3268: 'AD Global Catalog',
    3269: 'AD Global Catalog SSL',
    8080: 'HTTP-Alt/WSO2',
    8443: 'Entrust IG HTTPS/SOAP',
    8444: 'Entrust IG Admin',
    8445: 'Entrust IG Self-Service',
    9443: 'WSO2/Gateway HTTPS',
}

TLS_VERSIONS = {
    0x0300: 'SSL 3.0',
    0x0301: 'TLS 1.0',
    0x0302: 'TLS 1.1',
    0x0303: 'TLS 1.2',
    0x0304: 'TLS 1.3',
}

TLS_CIPHERS = {
    0x1301: 'TLS_AES_128_GCM_SHA256',
    0x1302: 'TLS_AES_256_GCM_SHA384',
    0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
    0xc02f: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    0xc030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    0xc02b: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
    0xc02c: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    0x009c: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
    0x009d: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
    0x002f: 'TLS_RSA_WITH_AES_128_CBC_SHA',
    0x0035: 'TLS_RSA_WITH_AES_256_CBC_SHA',
}

TLS_ALERTS = {
    0: 'close_notify',
    10: 'unexpected_message',
    20: 'bad_record_mac',
    21: 'decryption_failed',
    22: 'record_overflow',
    40: 'handshake_failure',
    41: 'no_certificate',
    42: 'bad_certificate',
    43: 'unsupported_certificate',
    44: 'certificate_revoked',
    45: 'certificate_expired',
    46: 'certificate_unknown',
    47: 'illegal_parameter',
    48: 'unknown_ca',
    49: 'access_denied',
    50: 'decode_error',
    51: 'decrypt_error',
    70: 'protocol_version',
    71: 'insufficient_security',
    80: 'internal_error',
    86: 'inappropriate_fallback',
    90: 'user_canceled',
    109: 'missing_extension',
    110: 'unsupported_extension',
    112: 'unrecognized_name',
    113: 'bad_certificate_status_response',
    116: 'certificate_required',
    120: 'no_application_protocol',
}

DNS_RCODES = {
    0: 'NOERROR',
    1: 'FORMERR',
    2: 'SERVFAIL',
    3: 'NXDOMAIN',
    4: 'NOTIMP',
    5: 'REFUSED',
}

DNS_QTYPES = {
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    6: 'SOA',
    12: 'PTR',
    15: 'MX',
    16: 'TXT',
    28: 'AAAA',
    33: 'SRV',
    255: 'ANY',
}

ICMP_V4_TYPES = {
    0: 'Echo Reply',
    3: 'Destination Unreachable',
    4: 'Source Quench',
    5: 'Redirect',
    8: 'Echo Request',
    11: 'Time Exceeded',
    12: 'Parameter Problem',
}

ICMP_V4_UNREACH_CODES = {
    0: 'Net Unreachable',
    1: 'Host Unreachable',
    2: 'Protocol Unreachable',
    3: 'Port Unreachable',
    4: 'Fragmentation Needed',
    9: 'Net Administratively Prohibited',
    10: 'Host Administratively Prohibited',
    13: 'Communication Administratively Prohibited',
}

ICMP_V6_TYPES = {
    1: 'Destination Unreachable',
    2: 'Packet Too Big',
    3: 'Time Exceeded',
    4: 'Parameter Problem',
    128: 'Echo Request',
    129: 'Echo Reply',
    135: 'Neighbor Solicitation',
    136: 'Neighbor Advertisement',
}


def format_ts_iso(ts_float):
    if ts_float is None or ts_float <= 0:
        return ''
    try:
        dt = datetime.datetime.fromtimestamp(ts_float)
        return dt.strftime('%Y-%m-%d %H:%M:%S.') + f'{int(dt.microsecond):06d}'
    except Exception:
        return ''


def identify_service(sport, dport):
    for p in (dport, sport):
        if p in SERVICE_PORT_LABELS:
            return SERVICE_PORT_LABELS[p]
    return ''


def canonical_flow_key(ip_a, port_a, ip_b, port_b, proto):
    ep1 = (str(ip_a or ''), int(port_a or 0))
    ep2 = (str(ip_b or ''), int(port_b or 0))
    if ep1 <= ep2:
        return f"{proto}|{ep1[0]}:{ep1[1]}<->{ep2[0]}:{ep2[1]}"
    return f"{proto}|{ep2[0]}:{ep2[1]}<->{ep1[0]}:{ep1[1]}"


def _open_maybe_gzip(file_path):
    with open(file_path, 'rb') as f:
        head = f.read(4)
    is_gz = len(head) >= 2 and head[0] == 0x1F and head[1] == 0x8B
    if is_gz:
        return gzip.open(file_path, 'rb'), True
    return open(file_path, 'rb'), False


def _read_pcap_frames(fh, first4, is_gz):
    hdr_rest = fh.read(20)
    if len(hdr_rest) < 20:
        raise ValueError('Cabecera PCAP truncada (< 24 bytes).')

    if first4 == b'\xa1\xb2\xc3\xd4':
        endian, is_ns = '>', False
    elif first4 == b'\xd4\xc3\xb2\xa1':
        endian, is_ns = '<', False
    elif first4 == b'\xa1\xb2\x3c\x4d':
        endian, is_ns = '>', True
    elif first4 == b'\x4d\x3c\xb2\xa1':
        endian, is_ns = '<', True
    else:
        raise ValueError('Magic number PCAP inválido.')

    _ver_maj, _ver_min, _thiszone, _sigfigs, _snaplen, linktype = struct.unpack(endian + 'HHIIII', hdr_rest)
    fmt_name = 'PCAP_GZ' if is_gz else 'PCAP'
    pkt_hdr_fmt = endian + 'IIII'

    frame_num = 0
    while True:
        rec_hdr = fh.read(16)
        if not rec_hdr:
            break
        if len(rec_hdr) < 16:
            break
        ts_sec, ts_sub, incl_len, orig_len = struct.unpack(pkt_hdr_fmt, rec_hdr)
        if incl_len > 16 * 1024 * 1024:
            raise ValueError(f'Paquete #{frame_num + 1} excede límite seguro ({incl_len} bytes). Archivo corrupto o no PCAP.')
        pkt_bytes = fh.read(incl_len)
        if len(pkt_bytes) < incl_len:
            break
        frame_num += 1
        ts_float = float(ts_sec) + (float(ts_sub) / (1e9 if is_ns else 1e6))
        yield {
            'format': fmt_name,
            'frame_num': frame_num,
            'ts': ts_float,
            'ts_str': format_ts_iso(ts_float),
            'linktype': linktype,
            'orig_len': orig_len,
            'raw_bytes': pkt_bytes,
        }


def _parse_if_tsresol(opts_bytes, endian):
    pos = 0
    tsresol = 1e-6
    n = len(opts_bytes)
    while pos + 4 <= n:
        opt_code, opt_len = struct.unpack(endian + 'HH', opts_bytes[pos:pos + 4])
        pos += 4
        if opt_code == 0:
            break
        val = opts_bytes[pos:pos + opt_len]
        pos += ((opt_len + 3) // 4) * 4
        if opt_code == 9 and len(val) >= 1:
            b = val[0]
            if b & 0x80:
                tsresol = 2.0 ** (-(b & 0x7F))
            else:
                tsresol = 10.0 ** (-b)
    return tsresol


def _read_pcapng_frames(fh, first4, is_gz):
    endian = '<'
    interfaces = []
    frame_num = 0
    fmt_name = 'PCAPNG_GZ' if is_gz else 'PCAPNG'

    pending_head = first4
    while True:
        hdr8 = (pending_head + fh.read(4)) if pending_head else fh.read(8)
        pending_head = None
        if not hdr8:
            break
        if len(hdr8) < 8:
            break

        raw_type_le, raw_len_le = struct.unpack('<II', hdr8)
        if raw_type_le == 0x0A0D0D0A:
            # Section Header Block determines byte order via bytes 8:12
            rest_shb_probe = fh.read(4)
            if len(rest_shb_probe) < 4:
                break
            if rest_shb_probe == b'\x4d\x3c\x2b\x1a':
                endian = '<'
            elif rest_shb_probe == b'\x1a\x2b\x3c\x4d':
                endian = '>'
            else:
                raise ValueError('Magic de orden de bytes PCAPNG inválido en Section Header Block.')
            block_type = 0x0A0D0D0A
            block_len = struct.unpack(endian + 'I', hdr8[4:8])[0]
            if block_len < 28 or block_len > 64 * 1024 * 1024:
                raise ValueError(f'Longitud de SHB PCAPNG inválida ({block_len}).')
            body = rest_shb_probe + fh.read(block_len - 12)
            interfaces = []
            continue

        block_type, block_len = struct.unpack(endian + 'II', hdr8)
        if block_len < 12 or block_len > 64 * 1024 * 1024:
            break
        remaining = fh.read(block_len - 8)
        if len(remaining) < block_len - 8:
            break
        body = remaining[:-4]  # strip trailing repeated block_total_length

        if block_type == 0x00000001 and len(body) >= 8:
            # Interface Description Block
            linktype, _res, snaplen = struct.unpack(endian + 'HHI', body[:8])
            tsresol = _parse_if_tsresol(body[8:], endian)
            interfaces.append({'linktype': linktype, 'snaplen': snaplen, 'tsresol': tsresol})
        elif block_type == 0x00000006 and len(body) >= 20:
            # Enhanced Packet Block
            iface_id, ts_hi, ts_lo, caplen, origlen = struct.unpack(endian + 'IIIII', body[:20])
            pkt_bytes = body[20:20 + caplen]
            if iface_id < len(interfaces):
                iface = interfaces[iface_id]
                linktype = iface['linktype']
                tsresol = iface['tsresol']
            else:
                linktype = 1
                tsresol = 1e-6
            ts_raw = (ts_hi << 32) | ts_lo
            ts_float = float(ts_raw) * tsresol
            frame_num += 1
            yield {
                'format': fmt_name,
                'frame_num': frame_num,
                'ts': ts_float,
                'ts_str': format_ts_iso(ts_float),
                'linktype': linktype,
                'orig_len': origlen,
                'raw_bytes': pkt_bytes,
            }
        elif block_type == 0x00000003 and len(body) >= 4:
            # Simple Packet Block
            origlen = struct.unpack(endian + 'I', body[:4])[0]
            pkt_bytes = body[4:4 + origlen]
            linktype = interfaces[0]['linktype'] if interfaces else 1
            frame_num += 1
            yield {
                'format': fmt_name,
                'frame_num': frame_num,
                'ts': 0.0,
                'ts_str': '',
                'linktype': linktype,
                'orig_len': origlen,
                'raw_bytes': pkt_bytes,
            }


_TCPDUMP_LINE_RE = re.compile(
    r'^(?:(\d{4}-\d{2}-\d{2})\s+)?(\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(IP6?)\s+([^\s>]+)\s+>\s+([^:\s]+):\s*(.*)$'
)


def _split_ip_port(ep_str):
    ep = ep_str.strip().rstrip(':')
    # Check trailing .port
    parts = ep.rsplit('.', 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0], int(parts[1])
    return ep, 0


def _read_tcpdump_text_packets(file_path):
    base_date = None
    frame_num = 0
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            m = _TCPDUMP_LINE_RE.match(s)
            if not m:
                continue
            date_part, time_part, ip_ver, src_raw, dst_raw, detail = m.groups()
            frame_num += 1
            src_ip, src_port = _split_ip_port(src_raw)
            dst_ip, dst_port = _split_ip_port(dst_raw)

            ts_float = 0.0
            ts_str = f'{date_part} {time_part}' if date_part else time_part
            if date_part:
                base_date = date_part
                try:
                    t_norm = time_part.split('.')[0]
                    us_part = time_part.split('.')[1] if '.' in time_part else '0'
                    us = int((us_part + '000000')[:6])
                    dt = datetime.datetime.strptime(f'{date_part} {t_norm}', '%Y-%m-%d %H:%M:%S').replace(microsecond=us)
                    ts_float = dt.timestamp()
                except Exception:
                    ts_float = 0.0
            else:
                # Relative seconds within capture day for RTT measurement without fabricating calendar date
                try:
                    hms = time_part.split('.')[0]
                    us_part = time_part.split('.')[1] if '.' in time_part else '0'
                    hh, mm, ss = [int(x) for x in hms.split(':')]
                    ts_float = hh * 3600.0 + mm * 60.0 + ss + int((us_part + '000000')[:6]) / 1e6
                except Exception:
                    ts_float = 0.0

            length = 0
            len_m = re.search(r'\blength\s+(\d+)', detail)
            if len_m:
                length = int(len_m.group(1))

            flags_m = re.search(r'Flags\s+\[([^\]]+)\]', detail)
            proto = 'TCP' if flags_m or ('seq ' in detail) or ('ack ' in detail) else ('UDP' if 'UDP' in detail else ('ICMP6' if 'ICMP6' in detail else ('ICMP' if 'ICMP' in detail else ip_ver)))
            tcp_flags = ''
            seq_val = None
            ack_val = None
            win_val = None
            if flags_m:
                raw_f = flags_m.group(1)
                f_parts = []
                if 'S' in raw_f:
                    f_parts.append('SYN')
                if '.' in raw_f or 'A' in raw_f:
                    f_parts.append('ACK')
                if 'F' in raw_f:
                    f_parts.append('FIN')
                if 'R' in raw_f:
                    f_parts.append('RST')
                if 'P' in raw_f:
                    f_parts.append('PSH')
                if 'U' in raw_f:
                    f_parts.append('URG')
                tcp_flags = ','.join(f_parts)
                seq_m = re.search(r'\bseq\s+(\d+)', detail)
                if seq_m:
                    seq_val = int(seq_m.group(1))
                ack_m = re.search(r'\back\s+(\d+)', detail)
                if ack_m:
                    ack_val = int(ack_m.group(1))
                win_m = re.search(r'\bwin\s+(\d+)', detail)
                if win_m:
                    win_val = int(win_m.group(1))

            yield {
                'format': 'TCPDUMP_TEXT',
                'frame_num': frame_num,
                'ts': ts_float,
                'ts_str': ts_str,
                'has_calendar_date': bool(date_part or base_date),
                'linktype_name': 'tcpdump-text',
                'src_ip': src_ip,
                'src_port': src_port,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'proto': proto,
                'app_proto': identify_service(src_port, dst_port) or proto,
                'length': length,
                'payload_len': length if proto == 'TCP' else 0,
                'tcp_flags': tcp_flags,
                'seq': seq_val,
                'ack': ack_val,
                'win': win_val,
                'severity': 'CRITICAL' if 'RST' in tcp_flags else 'INFO',
                'info': detail[:240],
                'is_encrypted': 0,
                'tls_info': None,
                'dns_info': None,
                'http_info': None,
                'icmp_error': ('unreachable' in detail.lower() or 'prohibited' in detail.lower()),
            }


def _decode_dns_name(buf, offset):
    labels = []
    pos = offset
    jumped = False
    end_pos = offset
    jumps = 0
    n = len(buf)
    while pos < n and jumps < 32:
        length = buf[pos]
        if length == 0:
            if not jumped:
                end_pos = pos + 1
            break
        if (length & 0xC0) == 0xC0:
            if pos + 1 >= n:
                break
            ptr = ((length & 0x3F) << 8) | buf[pos + 1]
            if not jumped:
                end_pos = pos + 2
            jumped = True
            pos = ptr
            jumps += 1
            continue
        pos += 1
        if pos + length > n:
            break
        labels.append(buf[pos:pos + length].decode('utf-8', errors='replace'))
        pos += length
        if not jumped:
            end_pos = pos
    return '.'.join(labels) if labels else '<root>', end_pos


def parse_dns(payload):
    if not payload or len(payload) < 12:
        return None
    tx_id, flags, qdcount, ancount, _nscount, _arcount = struct.unpack('>HHHHHH', payload[:12])
    qr = (flags >> 15) & 1
    rcode = flags & 0x0F
    if qdcount > 16 or ancount > 64:
        return None
    qname = ''
    qtype = 0
    if qdcount >= 1:
        qname, next_pos = _decode_dns_name(payload, 12)
        if next_pos + 4 <= len(payload):
            qtype, _qclass = struct.unpack('>HH', payload[next_pos:next_pos + 4])
    rcode_str = DNS_RCODES.get(rcode, f'RCODE_{rcode}')
    qtype_str = DNS_QTYPES.get(qtype, str(qtype))
    return {
        'tx_id': tx_id,
        'is_response': bool(qr),
        'rcode': rcode,
        'rcode_name': rcode_str,
        'qname': qname,
        'qtype': qtype_str,
    }


def _parse_tls_client_hello_exts(ext_bytes):
    pos = 0
    n = len(ext_bytes)
    sni = ''
    supported_ver = ''
    while pos + 4 <= n:
        etype, elen = struct.unpack('>HH', ext_bytes[pos:pos + 4])
        pos += 4
        if pos + elen > n:
            break
        eval_b = ext_bytes[pos:pos + elen]
        pos += elen
        if etype == 0x0000 and len(eval_b) >= 5:
            list_len = struct.unpack('>H', eval_b[:2])[0]
            if len(eval_b) >= 2 + list_len and eval_b[2] == 0:
                name_len = struct.unpack('>H', eval_b[3:5])[0]
                if 5 + name_len <= len(eval_b):
                    sni = eval_b[5:5 + name_len].decode('utf-8', errors='replace')
        elif etype == 0x002B and len(eval_b) >= 2:
            # supported_versions in ClientHello: 1-byte list length followed by 2-byte versions
            if eval_b[0] == len(eval_b) - 1:
                vers = [struct.unpack('>H', eval_b[i:i + 2])[0] for i in range(1, len(eval_b) - 1, 2)]
                for v in (0x0304, 0x0303, 0x0302, 0x0301):
                    if v in vers:
                        supported_ver = TLS_VERSIONS.get(v, '')
                        break
    return sni, supported_ver


def _parse_tls_server_hello_exts(ext_bytes):
    pos = 0
    n = len(ext_bytes)
    supported_ver = ''
    while pos + 4 <= n:
        etype, elen = struct.unpack('>HH', ext_bytes[pos:pos + 4])
        pos += 4
        if pos + elen > n:
            break
        eval_b = ext_bytes[pos:pos + elen]
        pos += elen
        if etype == 0x002B and len(eval_b) == 2:
            v = struct.unpack('>H', eval_b)[0]
            supported_ver = TLS_VERSIONS.get(v, f'0x{v:04x}')
    return supported_ver


def parse_tls_records(payload):
    if not payload or len(payload) < 6:
        return None
    pos = 0
    n = len(payload)
    first_ctype = payload[0]
    first_ver = struct.unpack('>H', payload[1:3])[0]
    if first_ctype not in (20, 21, 22, 23) or first_ver not in (0x0300, 0x0301, 0x0302, 0x0303, 0x0304):
        return None

    events = []
    sni = ''
    negotiated_ver = ''
    fallback_rec_ver = TLS_VERSIONS.get(first_ver, f'0x{first_ver:04x}')
    cipher_name = ''
    alert_info = None
    is_encrypted = False
    cert_count = 0

    while pos + 5 <= n:
        ctype = payload[pos]
        ver = struct.unpack('>H', payload[pos + 1:pos + 3])[0]
        rec_len = struct.unpack('>H', payload[pos + 3:pos + 5])[0]
        if ctype not in (20, 21, 22, 23) or ver not in (0x0300, 0x0301, 0x0302, 0x0303, 0x0304):
            break
        if rec_len == 0 or pos + 5 + rec_len > n:
            # Allow truncated capture of Application Data or Handshake if record header is valid
            rec = payload[pos + 5:]
            pos = n
        else:
            rec = payload[pos + 5:pos + 5 + rec_len]
            pos += 5 + rec_len

        if ctype == 20:
            events.append('ChangeCipherSpec')
        elif ctype == 23:
            is_encrypted = True
            events.append('Application Data')
        elif ctype == 21 and len(rec) >= 2:
            lvl_num, desc_num = rec[0], rec[1]
            if lvl_num in (1, 2):
                lvl_str = 'Fatal' if lvl_num == 2 else 'Warning'
                desc_str = TLS_ALERTS.get(desc_num, f'alert_{desc_num}')
                alert_info = {'level': lvl_str, 'code': desc_num, 'name': desc_str}
                events.append(f'Alert ({lvl_str}: {desc_str} [{desc_num}])')
            else:
                # Encrypted TLS 1.3 alert inside ChangeCipherSpec epoch
                is_encrypted = True
                events.append('Encrypted Alert')
        elif ctype == 22 and len(rec) >= 4:
            hs_type = rec[0]
            hs_body = rec[4:]
            if hs_type == 1 and len(hs_body) >= 34:
                cli_ver = struct.unpack('>H', hs_body[:2])[0]
                negotiated_ver = TLS_VERSIONS.get(cli_ver, negotiated_ver)
                idx = 34
                if idx < len(hs_body):
                    sid_len = hs_body[idx]
                    idx += 1 + sid_len
                if idx + 2 <= len(hs_body):
                    cs_len = struct.unpack('>H', hs_body[idx:idx + 2])[0]
                    idx += 2 + cs_len
                if idx < len(hs_body):
                    comp_len = hs_body[idx]
                    idx += 1 + comp_len
                if idx + 2 <= len(hs_body):
                    exts_len = struct.unpack('>H', hs_body[idx:idx + 2])[0]
                    exts_b = hs_body[idx + 2:idx + 2 + exts_len]
                    ext_sni, ext_ver = _parse_tls_client_hello_exts(exts_b)
                    if ext_sni:
                        sni = ext_sni
                    if ext_ver:
                        negotiated_ver = ext_ver
                events.append(f'ClientHello ({negotiated_ver}' + (f', SNI={sni}' if sni else '') + ')')
            elif hs_type == 2 and len(hs_body) >= 34:
                srv_ver = struct.unpack('>H', hs_body[:2])[0]
                negotiated_ver = TLS_VERSIONS.get(srv_ver, negotiated_ver)
                idx = 34
                if idx < len(hs_body):
                    sid_len = hs_body[idx]
                    idx += 1 + sid_len
                if idx + 3 <= len(hs_body):
                    cipher_id = struct.unpack('>H', hs_body[idx:idx + 2])[0]
                    cipher_name = TLS_CIPHERS.get(cipher_id, f'0x{cipher_id:04x}')
                    idx += 3  # 2-byte cipher + 1-byte compression
                if idx + 2 <= len(hs_body):
                    exts_len = struct.unpack('>H', hs_body[idx:idx + 2])[0]
                    exts_b = hs_body[idx + 2:idx + 2 + exts_len]
                    ext_ver = _parse_tls_server_hello_exts(exts_b)
                    if ext_ver:
                        negotiated_ver = ext_ver
                events.append(f'ServerHello ({negotiated_ver}, Cipher={cipher_name})')
            elif hs_type == 11 and len(hs_body) >= 3:
                # TLS Certificate message: 3-byte total cert chain len + list of 3-byte cert lens
                total_clen = int.from_bytes(hs_body[:3], 'big')
                cpos = 3
                limit = min(len(hs_body), 3 + total_clen)
                while cpos + 3 <= limit:
                    clen = int.from_bytes(hs_body[cpos:cpos + 3], 'big')
                    if clen == 0 or cpos + 3 + clen > len(hs_body):
                        break
                    cert_count += 1
                    cpos += 3 + clen
                events.append(f'Certificate ({cert_count} cert(s))' if cert_count else 'Certificate')
            elif hs_type == 12:
                events.append('ServerKeyExchange')
            elif hs_type == 14:
                events.append('ServerHelloDone')
            elif hs_type == 16:
                events.append('ClientKeyExchange')
            else:
                events.append(f'Handshake({hs_type})')

    if not events:
        return None

    return {
        'events': events,
        'version': negotiated_ver,
        'sni': sni,
        'cipher': cipher_name,
        'alert': alert_info,
        'is_encrypted': is_encrypted,
        'cert_count': cert_count,
    }


_HTTP_REQ_RE = re.compile(rb'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\r\n\s]+)\s+HTTP/1\.[01]\r?\n')
_HTTP_RESP_RE = re.compile(rb'^HTTP/1\.[01]\s+(\d{3})\s+([^\r\n]*)')


def parse_http_cleartext(payload):
    if not payload or len(payload) < 12:
        return None
    m_req = _HTTP_REQ_RE.match(payload[:512])
    if m_req:
        method = m_req.group(1).decode('ascii', errors='replace')
        path = m_req.group(2).decode('utf-8', errors='replace')
        return {'kind': 'REQUEST', 'method': method, 'path': path[:120], 'status': None}
    m_resp = _HTTP_RESP_RE.match(payload[:256])
    if m_resp:
        status = int(m_resp.group(1))
        reason = m_resp.group(2).decode('utf-8', errors='replace').strip()
        return {'kind': 'RESPONSE', 'status': status, 'reason': reason[:80]}
    return None


def _unwrap_link_layer(raw_bytes, linktype):
    if linktype == 1:  # Ethernet
        if len(raw_bytes) < 14:
            return None, b''
        ethertype = struct.unpack('>H', raw_bytes[12:14])[0]
        offset = 14
        while ethertype in (0x8100, 0x88A8) and offset + 4 <= len(raw_bytes):
            ethertype = struct.unpack('>H', raw_bytes[offset + 2:offset + 4])[0]
            offset += 4
        return ethertype, raw_bytes[offset:]
    if linktype == 113:  # DLT_LINUX_SLL (tcpdump -i any v1)
        if len(raw_bytes) < 16:
            return None, b''
        ethertype = struct.unpack('>H', raw_bytes[14:16])[0]
        return ethertype, raw_bytes[16:]
    if linktype == 276:  # DLT_LINUX_SLL2 (tcpdump -i any v2, RHEL 9)
        if len(raw_bytes) < 20:
            return None, b''
        ethertype = struct.unpack('>H', raw_bytes[0:2])[0]
        return ethertype, raw_bytes[20:]
    if linktype in (101, 228, 229):  # Raw IP
        if len(raw_bytes) < 1:
            return None, b''
        ver = raw_bytes[0] >> 4
        return (0x0800 if ver == 4 else (0x86DD if ver == 6 else None)), raw_bytes
    if linktype in (0, 108):  # Loopback NULL
        if len(raw_bytes) < 4:
            return None, b''
        af_le = struct.unpack('<I', raw_bytes[:4])[0]
        af_be = struct.unpack('>I', raw_bytes[:4])[0]
        if 2 in (af_le, af_be):
            return 0x0800, raw_bytes[4:]
        if any(x in (24, 28, 30, 10) for x in (af_le, af_be)):
            return 0x86DD, raw_bytes[4:]
    return None, b''


def decode_binary_packet(frame):
    raw = frame['raw_bytes']
    ethertype, net_pkt = _unwrap_link_layer(raw, frame['linktype'])
    base = {
        'format': frame['format'],
        'frame_num': frame['frame_num'],
        'ts': frame['ts'],
        'ts_str': frame['ts_str'],
        'has_calendar_date': bool(frame['ts'] > 0),
        'linktype_name': DLT_NAMES.get(frame['linktype'], f'DLT_{frame["linktype"]}'),
        'src_ip': '',
        'src_port': 0,
        'dst_ip': '',
        'dst_port': 0,
        'proto': 'OTHER',
        'app_proto': 'OTHER',
        'length': frame['orig_len'] or len(raw),
        'payload_len': 0,
        'tcp_flags': '',
        'seq': None,
        'ack': None,
        'win': None,
        'severity': 'INFO',
        'info': f'Ethertype 0x{ethertype:04x}' if ethertype is not None else 'Unsupported Link Frame',
        'is_encrypted': 0,
        'tls_info': None,
        'dns_info': None,
        'http_info': None,
        'icmp_error': False,
    }

    if ethertype == 0x0806 and len(net_pkt) >= 28:
        op = struct.unpack('>H', net_pkt[6:8])[0]
        spa = socket.inet_ntop(socket.AF_INET, net_pkt[14:18])
        tpa = socket.inet_ntop(socket.AF_INET, net_pkt[24:28])
        base['proto'] = 'ARP'
        base['app_proto'] = 'ARP'
        base['src_ip'] = spa
        base['dst_ip'] = tpa
        base['info'] = f'ARP Request: Who has {tpa}? Tell {spa}' if op == 1 else f'ARP Reply: {spa} is at target'
        return base

    l4_proto = None
    l4_bytes = b''

    if ethertype == 0x0800 and len(net_pkt) >= 20:
        ihl = (net_pkt[0] & 0x0F) * 4
        tot_len = struct.unpack('>H', net_pkt[2:4])[0]
        l4_proto = net_pkt[9]
        base['src_ip'] = socket.inet_ntop(socket.AF_INET, net_pkt[12:16])
        base['dst_ip'] = socket.inet_ntop(socket.AF_INET, net_pkt[16:20])
        end_ip = min(len(net_pkt), max(ihl, tot_len)) if tot_len >= ihl else len(net_pkt)
        l4_bytes = net_pkt[ihl:end_ip] if ihl >= 20 else b''
    elif ethertype == 0x86DD and len(net_pkt) >= 40:
        plen = struct.unpack('>H', net_pkt[4:6])[0]
        nh = net_pkt[6]
        base['src_ip'] = socket.inet_ntop(socket.AF_INET6, net_pkt[8:24])
        base['dst_ip'] = socket.inet_ntop(socket.AF_INET6, net_pkt[24:40])
        offset = 40
        limit = min(len(net_pkt), 40 + plen) if plen > 0 else len(net_pkt)
        while nh in (0, 43, 44, 60) and offset + 8 <= limit:
            if nh == 44:
                nh = net_pkt[offset]
                offset += 8
            else:
                nh = net_pkt[offset]
                hdr_len = (net_pkt[offset + 1] + 1) * 8
                offset += hdr_len
        l4_proto = nh
        l4_bytes = net_pkt[offset:limit]
    else:
        return base

    if l4_proto == 1 and len(l4_bytes) >= 4:
        icmp_type, icmp_code = l4_bytes[0], l4_bytes[1]
        base['proto'] = 'ICMP'
        base['app_proto'] = 'ICMP'
        t_name = ICMP_V4_TYPES.get(icmp_type, f'Type {icmp_type}')
        if icmp_type == 3:
            c_name = ICMP_V4_UNREACH_CODES.get(icmp_code, f'Code {icmp_code}')
            base['info'] = f'ICMP {t_name} ({c_name})'
            base['severity'] = 'CRITICAL' if icmp_code in (3, 9, 10, 13) else 'WARN'
            base['icmp_error'] = True
        elif icmp_type == 11:
            base['info'] = f'ICMP {t_name} (TTL/Reassembly)'
            base['severity'] = 'WARN'
            base['icmp_error'] = True
        else:
            base['info'] = f'ICMP {t_name}'
        return base

    if l4_proto == 58 and len(l4_bytes) >= 4:
        icmp_type, icmp_code = l4_bytes[0], l4_bytes[1]
        base['proto'] = 'ICMPv6'
        base['app_proto'] = 'ICMPv6'
        t_name = ICMP_V6_TYPES.get(icmp_type, f'Type {icmp_type}')
        base['info'] = f'ICMPv6 {t_name} (code {icmp_code})'
        if icmp_type in (1, 2, 3):
            base['severity'] = 'CRITICAL' if icmp_type == 1 else 'WARN'
            base['icmp_error'] = True
        return base

    if l4_proto == 6 and len(l4_bytes) >= 20:
        sport, dport, seq_n, ack_n, off_flags, flags_b, win_n = struct.unpack('>HHIIBBH', l4_bytes[:16])
        data_off = ((off_flags >> 4) & 0x0F) * 4
        payload = l4_bytes[data_off:] if 20 <= data_off <= len(l4_bytes) else b''
        f_list = []
        if flags_b & 0x02:
            f_list.append('SYN')
        if flags_b & 0x10:
            f_list.append('ACK')
        if flags_b & 0x01:
            f_list.append('FIN')
        if flags_b & 0x04:
            f_list.append('RST')
        if flags_b & 0x08:
            f_list.append('PSH')
        if flags_b & 0x20:
            f_list.append('URG')
        flags_str = ','.join(f_list)
        svc = identify_service(sport, dport)

        base['proto'] = 'TCP'
        base['src_port'] = sport
        base['dst_port'] = dport
        base['tcp_flags'] = flags_str
        base['seq'] = seq_n
        base['ack'] = ack_n
        base['win'] = win_n
        base['payload_len'] = len(payload)
        base['app_proto'] = svc or 'TCP'

        tls = parse_tls_records(payload) if payload else None
        if tls:
            base['tls_info'] = tls
            base['app_proto'] = tls['version'] or 'TLS'
            if tls['is_encrypted']:
                base['is_encrypted'] = 1
            base['info'] = f"TLS [{'; '.join(tls['events'])}]"
            if tls['is_encrypted'] and len(tls['events']) == 1 and tls['events'][0] == 'Application Data':
                base['info'] = 'TLS Application Data (payload cifrado — no inspeccionable sin clave)'
            if tls['alert']:
                base['severity'] = 'CRITICAL' if tls['alert']['level'] == 'Fatal' else 'WARN'
        else:
            http = parse_http_cleartext(payload) if payload else None
            if http:
                base['http_info'] = http
                base['app_proto'] = 'HTTP/SOAP'
                if http['kind'] == 'REQUEST':
                    base['info'] = f"HTTP {http['method']} {http['path']}"
                else:
                    st_c = http['status']
                    base['info'] = f"HTTP {st_c} {http['reason']}"
                    if st_c >= 500:
                        base['severity'] = 'CRITICAL'
                    elif st_c >= 400:
                        base['severity'] = 'WARN'
            elif (53 in (sport, dport)) and len(payload) >= 14:
                # DNS over TCP has 2-byte length prefix
                dns = parse_dns(payload[2:])
                if dns:
                    base['dns_info'] = dns
                    base['app_proto'] = 'DNS'
                    kind_s = 'Response' if dns['is_response'] else 'Query'
                    base['info'] = f"DNS/TCP {kind_s}: {dns['qtype']} {dns['qname']} [{dns['rcode_name']}]"
                    if dns['is_response'] and dns['rcode'] != 0:
                        base['severity'] = 'CRITICAL' if dns['rcode'] in (2, 5) else 'WARN'
            else:
                info_parts = [f'[{flags_str or "TCP"}]']
                if svc:
                    info_parts.append(svc)
                info_parts.append(f'seq={seq_n} win={win_n} len={len(payload)}')
                base['info'] = ' '.join(info_parts)

        if 'RST' in f_list:
            base['severity'] = 'CRITICAL'
        elif win_n == 0 and 'SYN' not in f_list and 'RST' not in f_list and base['severity'] == 'INFO':
            base['severity'] = 'WARN'
            base['info'] += ' [TCP ZeroWindow]'
        return base

    if l4_proto == 17 and len(l4_bytes) >= 8:
        sport, dport, ulen, _csum = struct.unpack('>HHHH', l4_bytes[:8])
        payload = l4_bytes[8:min(len(l4_bytes), ulen)] if ulen >= 8 else l4_bytes[8:]
        svc = identify_service(sport, dport)
        base['proto'] = 'UDP'
        base['src_port'] = sport
        base['dst_port'] = dport
        base['payload_len'] = len(payload)
        base['app_proto'] = svc or 'UDP'

        if 53 in (sport, dport) and payload:
            dns = parse_dns(payload)
            if dns:
                base['dns_info'] = dns
                base['app_proto'] = 'DNS'
                kind_s = 'Response' if dns['is_response'] else 'Query'
                base['info'] = f"DNS {kind_s}: {dns['qtype']} {dns['qname']}" + (f" [{dns['rcode_name']}]" if dns['is_response'] else '')
                if dns['is_response'] and dns['rcode'] != 0:
                    base['severity'] = 'CRITICAL' if dns['rcode'] in (2, 5) else 'WARN'
                return base

        base['info'] = f"{svc or 'UDP'} {sport} -> {dport} len={len(payload)}"
        return base

    base['proto'] = f'IP_PROTO_{l4_proto}'
    base['info'] = f'IP Protocol {l4_proto} len={len(l4_bytes)}'
    return base


def _iter_capture_packets(file_path):
    fh, is_gz = _open_maybe_gzip(file_path)
    first4 = b''
    try:
        first4 = fh.read(4)
        if not first4:
            raise ValueError('El archivo de captura está vacío (0 bytes).')

        if first4 in (b'\xa1\xb2\xc3\xd4', b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\x3c\x4d', b'\x4d\x3c\xb2\xa1'):
            for frame in _read_pcap_frames(fh, first4, is_gz):
                yield decode_binary_packet(frame)
            return

        if first4 == b'\x0a\x0d\x0d\x0a':
            for frame in _read_pcapng_frames(fh, first4, is_gz):
                yield decode_binary_packet(frame)
            return
    finally:
        fh.close()

    if is_gz:
        raise ValueError('Archivo .gz no contiene cabecera binaria PCAP/PCAPNG válida.')

    # Try plain tcpdump text lines
    parsed_any = False
    for pkt in _read_tcpdump_text_packets(file_path):
        parsed_any = True
        yield pkt
    if not parsed_any:
        raise ValueError(
            'Formato no reconocido: el archivo no es un PCAP/PCAPNG válido de Wireshark ni una salida de texto de tcpdump.'
        )


def analyze_pcap_to_sqlite(file_path, db_path, progress_callback=None):
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f'No se encontró el archivo: {file_path}')

    file_size = os.path.getsize(file_path)
    tmp_db = db_path + '.tmp'
    for candidate in (tmp_db, db_path):
        if os.path.exists(candidate):
            try:
                os.remove(candidate)
            except Exception:
                pass

    conn = sqlite3.connect(tmp_db, timeout=30.0)
    cur = conn.cursor()
    cur.execute('PRAGMA synchronous = OFF;')
    cur.execute('PRAGMA journal_mode = WAL;')
    cur.execute('''
        CREATE TABLE pcap_packets (
            frame_num INTEGER PRIMARY KEY,
            ts REAL,
            ts_str TEXT,
            src_ip TEXT,
            src_port INTEGER,
            dst_ip TEXT,
            dst_port INTEGER,
            proto TEXT,
            app_proto TEXT,
            length INTEGER,
            tcp_flags TEXT,
            severity TEXT,
            info TEXT,
            is_encrypted INTEGER,
            flow_key TEXT
        )
    ''')
    cur.execute('CREATE TABLE pcap_meta (key TEXT PRIMARY KEY, value TEXT)')

    proto_counts = collections.Counter()
    service_counts = collections.Counter()
    link_types = set()
    capture_format = ''
    has_calendar_date = False

    start_ts = None
    end_ts = None
    start_ts_str = ''
    end_ts_str = ''
    total_packets = 0
    total_bytes = 0

    anomalies = {
        'unansweredSyn': 0,
        'tcpRst': 0,
        'retransmissions': 0,
        'zeroWindow': 0,
        'tlsAlerts': 0,
        'dnsErrors': 0,
        'httpErrors': 0,
        'icmpErrors': 0,
    }
    findings = []
    rtt_samples = []
    flows = {}
    seen_segments = collections.defaultdict(set)
    tls_sessions = {}

    def _add_finding(frame_num, ts_str, category, severity, src, dst, service, evidence, flow_key):
        if len(findings) < 400:
            findings.append({
                'frameNum': frame_num,
                'timestamp': ts_str,
                'category': category,
                'severity': severity,
                'src': src,
                'dst': dst,
                'service': service,
                'evidence': evidence,
                'flowKey': flow_key,
            })

    batch = []
    batch_size = 5000

    try:
        for pkt in _iter_capture_packets(file_path):
            total_packets += 1
            total_bytes += int(pkt['length'] or 0)
            capture_format = pkt['format']
            if pkt.get('has_calendar_date'):
                has_calendar_date = True
            if pkt.get('linktype_name'):
                link_types.add(pkt['linktype_name'])

            proto_counts[pkt['proto']] += 1
            if pkt['app_proto'] and pkt['app_proto'] != pkt['proto']:
                service_counts[pkt['app_proto']] += 1
            else:
                svc_fallback = identify_service(pkt['src_port'], pkt['dst_port'])
                if svc_fallback:
                    service_counts[svc_fallback] += 1

            ts = pkt['ts']
            ts_str = pkt['ts_str']
            if ts > 0:
                if start_ts is None or ts < start_ts:
                    start_ts = ts
                    start_ts_str = ts_str
                if end_ts is None or ts > end_ts:
                    end_ts = ts
                    end_ts_str = ts_str
            elif ts_str:
                if not start_ts_str:
                    start_ts_str = ts_str
                end_ts_str = ts_str

            fk = canonical_flow_key(pkt['src_ip'], pkt['src_port'], pkt['dst_ip'], pkt['dst_port'], pkt['proto'])
            src_ep = f"{pkt['src_ip']}:{pkt['src_port']}" if pkt['src_port'] else pkt['src_ip']
            dst_ep = f"{pkt['dst_ip']}:{pkt['dst_port']}" if pkt['dst_port'] else pkt['dst_ip']
            svc_label = identify_service(pkt['src_port'], pkt['dst_port']) or pkt['app_proto']

            if fk not in flows:
                flows[fk] = {
                    'flowKey': fk,
                    'proto': pkt['proto'],
                    'service': svc_label,
                    'srcIp': pkt['src_ip'],
                    'srcPort': pkt['src_port'],
                    'dstIp': pkt['dst_ip'],
                    'dstPort': pkt['dst_port'],
                    'packets': 0,
                    'bytes': 0,
                    'firstSeen': ts_str,
                    'lastSeen': ts_str,
                    'synFrames': [],
                    'synTs': None,
                    'synAckSeen': False,
                    'rttMs': None,
                    'rstCount': 0,
                    'retransCount': 0,
                    'zeroWinCount': 0,
                    'tlsVersion': '',
                    'tlsSni': '',
                    'tlsCipher': '',
                    'tlsAlerts': [],
                    'isEncrypted': False,
                }
            fl = flows[fk]
            fl['packets'] += 1
            fl['bytes'] += int(pkt['length'] or 0)
            if ts_str:
                fl['lastSeen'] = ts_str
            if fl['service'] in ('TCP', 'UDP', '') and svc_label not in ('TCP', 'UDP', ''):
                fl['service'] = svc_label
            if pkt['is_encrypted']:
                fl['isEncrypted'] = True

            if pkt['proto'] == 'TCP':
                flags_set = set(pkt['tcp_flags'].split(',')) if pkt['tcp_flags'] else set()
                dir_key = (pkt['src_ip'], pkt['src_port'], pkt['dst_ip'], pkt['dst_port'])
                seq_v = pkt['seq']
                plen = pkt['payload_len']

                if 'SYN' in flags_set and 'ACK' not in flags_set:
                    fl['synFrames'].append(pkt['frame_num'])
                    if fl['synTs'] is None and ts > 0:
                        fl['synTs'] = ts
                    if seq_v is not None:
                        seg_id = ('SYN', seq_v)
                        if seg_id in seen_segments[dir_key]:
                            fl['retransCount'] += 1
                            anomalies['retransmissions'] += 1
                            if pkt['severity'] == 'INFO':
                                pkt['severity'] = 'WARN'
                            pkt['info'] += ' [TCP SYN Retransmission]'
                            _add_finding(
                                pkt['frame_num'], ts_str, 'TCP_RETRANSMISSION', 'WARN',
                                src_ep, dst_ep, svc_label,
                                f'Frame #{pkt["frame_num"]}: Retransmisión de SYN (seq={seq_v})', fk
                            )
                        else:
                            seen_segments[dir_key].add(seg_id)
                elif 'SYN' in flags_set and 'ACK' in flags_set:
                    fl['synAckSeen'] = True
                    if fl['synTs'] is not None and ts >= fl['synTs'] and fl['rttMs'] is None:
                        rtt_ms = round((ts - fl['synTs']) * 1000.0, 2)
                        fl['rttMs'] = rtt_ms
                        rtt_samples.append(rtt_ms)
                else:
                    if plen > 0 and seq_v is not None:
                        seg_id = ('DATA', seq_v, plen)
                        if seg_id in seen_segments[dir_key]:
                            fl['retransCount'] += 1
                            anomalies['retransmissions'] += 1
                            if pkt['severity'] == 'INFO':
                                pkt['severity'] = 'WARN'
                            pkt['info'] += ' [TCP Retransmission]'
                            _add_finding(
                                pkt['frame_num'], ts_str, 'TCP_RETRANSMISSION', 'WARN',
                                src_ep, dst_ep, svc_label,
                                f'Frame #{pkt["frame_num"]}: Retransmisión TCP detectada (seq={seq_v}, {plen} bytes)', fk
                            )
                        else:
                            if len(seen_segments[dir_key]) < 50000:
                                seen_segments[dir_key].add(seg_id)

                if 'RST' in flags_set:
                    fl['rstCount'] += 1
                    anomalies['tcpRst'] += 1
                    _add_finding(
                        pkt['frame_num'], ts_str, 'TCP_RST', 'CRITICAL',
                        src_ep, dst_ep, svc_label,
                        f'Frame #{pkt["frame_num"]}: Paquete TCP RST emitido por {src_ep} hacia {dst_ep}', fk
                    )

                if pkt['win'] == 0 and 'SYN' not in flags_set and 'RST' not in flags_set:
                    fl['zeroWinCount'] += 1
                    anomalies['zeroWindow'] += 1
                    _add_finding(
                        pkt['frame_num'], ts_str, 'TCP_ZERO_WINDOW', 'WARN',
                        src_ep, dst_ep, svc_label,
                        f'Frame #{pkt["frame_num"]}: TCP Zero Window reportado por {src_ep}', fk
                    )

            tls = pkt.get('tls_info')
            if tls:
                if tls['version'] and (not fl['tlsVersion'] or tls['version'] == 'TLS 1.3'):
                    fl['tlsVersion'] = tls['version']
                if tls['sni']:
                    fl['tlsSni'] = tls['sni']
                if tls['cipher']:
                    fl['tlsCipher'] = tls['cipher']
                if fk not in tls_sessions:
                    tls_sessions[fk] = {
                        'flowKey': fk,
                        'src': src_ep,
                        'dst': dst_ep,
                        'service': svc_label,
                        'version': tls['version'] or '',
                        'sni': tls['sni'],
                        'cipher': tls['cipher'],
                        'alerts': [],
                        'isEncrypted': bool(tls['is_encrypted']),
                        'firstFrame': pkt['frame_num'],
                        'timestamp': ts_str,
                    }
                ts_rec = tls_sessions[fk]
                if tls['version'] and (not ts_rec['version'] or tls['version'] == 'TLS 1.3'):
                    ts_rec['version'] = tls['version']
                if tls['sni']:
                    ts_rec['sni'] = tls['sni']
                if tls['cipher']:
                    ts_rec['cipher'] = tls['cipher']
                if tls['is_encrypted']:
                    ts_rec['isEncrypted'] = True
                if tls['alert']:
                    anomalies['tlsAlerts'] += 1
                    al_label = f"{tls['alert']['level']}: {tls['alert']['name']} (code {tls['alert']['code']})"
                    fl['tlsAlerts'].append(al_label)
                    ts_rec['alerts'].append(al_label)
                    _add_finding(
                        pkt['frame_num'], ts_str, 'TLS_ALERT',
                        'CRITICAL' if tls['alert']['level'] == 'Fatal' else 'WARN',
                        src_ep, dst_ep, svc_label,
                        f'Frame #{pkt["frame_num"]}: TLS Alert {al_label}' + (f" [SNI={fl['tlsSni']}]" if fl['tlsSni'] else ''),
                        fk,
                    )

            dns = pkt.get('dns_info')
            if dns and dns['is_response'] and dns['rcode'] != 0:
                anomalies['dnsErrors'] += 1
                _add_finding(
                    pkt['frame_num'], ts_str, f"DNS_{dns['rcode_name']}",
                    'CRITICAL' if dns['rcode'] in (2, 5) else 'WARN',
                    src_ep, dst_ep, 'DNS',
                    f"Frame #{pkt['frame_num']}: DNS {dns['qtype']} {dns['qname']} devolvió {dns['rcode_name']} (RCODE {dns['rcode']})",
                    fk,
                )

            http = pkt.get('http_info')
            if http and http.get('status') and http['status'] >= 400:
                anomalies['httpErrors'] += 1
                _add_finding(
                    pkt['frame_num'], ts_str, f"HTTP_{http['status']}",
                    'CRITICAL' if http['status'] >= 500 else 'WARN',
                    src_ep, dst_ep, svc_label,
                    f"Frame #{pkt['frame_num']}: Respuesta HTTP {http['status']} {http['reason']}",
                    fk,
                )

            if pkt.get('icmp_error'):
                anomalies['icmpErrors'] += 1
                _add_finding(
                    pkt['frame_num'], ts_str, 'ICMP_ERROR', pkt['severity'],
                    pkt['src_ip'], pkt['dst_ip'], 'ICMP',
                    f"Frame #{pkt['frame_num']}: {pkt['info']}", fk
                )

            batch.append((
                pkt['frame_num'],
                pkt['ts'],
                ts_str,
                pkt['src_ip'],
                pkt['src_port'],
                pkt['dst_ip'],
                pkt['dst_port'],
                pkt['proto'],
                pkt['app_proto'],
                pkt['length'],
                pkt['tcp_flags'],
                pkt['severity'],
                pkt['info'][:500],
                pkt['is_encrypted'],
                fk,
            ))

            if len(batch) >= batch_size:
                cur.executemany('INSERT INTO pcap_packets VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', batch)
                conn.commit()
                batch = []
                if progress_callback:
                    progress_callback(total_packets, total_bytes)

        if batch:
            cur.executemany('INSERT INTO pcap_packets VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', batch)
            conn.commit()

        # Post-pass: detect Unanswered SYN flows (SYN sent, no SYN-ACK, no RST)
        for fk, fl in flows.items():
            if fl['proto'] == 'TCP' and fl['synFrames'] and not fl['synAckSeen'] and fl['rstCount'] == 0:
                anomalies['unansweredSyn'] += 1
                src_ep = f"{fl['srcIp']}:{fl['srcPort']}" if fl['srcPort'] else fl['srcIp']
                dst_ep = f"{fl['dstIp']}:{fl['dstPort']}" if fl['dstPort'] else fl['dstIp']
                _add_finding(
                    fl['synFrames'][0], fl['firstSeen'], 'TCP_UNANSWERED_SYN', 'CRITICAL',
                    src_ep, dst_ep, fl['service'],
                    f"Frames {fl['synFrames'][:5]}: SYN enviado ({len(fl['synFrames'])} intento(s)) sin SYN-ACK ni RST (posible bloqueo/drop de firewall o servicio detenido)",
                    fk,
                )

        cur.execute('CREATE INDEX IF NOT EXISTS idx_pcap_sev ON pcap_packets(severity)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_pcap_proto ON pcap_packets(proto)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_pcap_src ON pcap_packets(src_ip)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_pcap_dst ON pcap_packets(dst_ip)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_pcap_flow ON pcap_packets(flow_key)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_pcap_ts ON pcap_packets(ts_str)')

        sev_rank = {'CRITICAL': 0, 'WARN': 1, 'INFO': 2}
        findings.sort(key=lambda x: (sev_rank.get(x['severity'], 9), x['frameNum']))

        sorted_flows = sorted(
            flows.values(),
            key=lambda f: (
                1 if (f['rstCount'] > 0 or f['tlsAlerts'] or (f['synFrames'] and not f['synAckSeen'])) else 0,
                f['rstCount'] + f['retransCount'] + len(f['tlsAlerts']),
                f['packets'],
            ),
            reverse=True,
        )
        flows_out = []
        for f in sorted_flows[:250]:
            flows_out.append({
                'flowKey': f['flowKey'],
                'proto': f['proto'],
                'service': f['service'],
                'srcIp': f['srcIp'],
                'srcPort': f['srcPort'],
                'dstIp': f['dstIp'],
                'dstPort': f['dstPort'],
                'packets': f['packets'],
                'bytes': f['bytes'],
                'firstSeen': f['firstSeen'],
                'lastSeen': f['lastSeen'],
                'rttMs': f['rttMs'],
                'rstCount': f['rstCount'],
                'retransCount': f['retransCount'],
                'zeroWinCount': f['zeroWinCount'],
                'unansweredSyn': bool(f['synFrames'] and not f['synAckSeen'] and f['rstCount'] == 0),
                'tlsVersion': f['tlsVersion'],
                'tlsSni': f['tlsSni'],
                'tlsCipher': f['tlsCipher'],
                'tlsAlerts': f['tlsAlerts'],
                'isEncrypted': f['isEncrypted'],
            })

        rtt_stats = {
            'samples': len(rtt_samples),
            'minMs': round(min(rtt_samples), 2) if rtt_samples else None,
            'medianMs': round(statistics.median(rtt_samples), 2) if rtt_samples else None,
            'maxMs': round(max(rtt_samples), 2) if rtt_samples else None,
        }
        duration_sec = round(max(0.0, end_ts - start_ts), 3) if (start_ts is not None and end_ts is not None) else 0.0
        encrypted_flows = sum(1 for f in flows.values() if f['isEncrypted'])

        summary_payload = {
            'status': 'ready',
            'fileName': os.path.basename(file_path),
            'fileSizeMb': round(file_size / (1024 * 1024), 2),
            'captureFormat': capture_format or 'UNKNOWN',
            'linkTypes': sorted(link_types),
            'hasCalendarDate': has_calendar_date,
            'startTime': start_ts_str or 'N/A',
            'endTime': end_ts_str or 'N/A',
            'durationSeconds': duration_sec,
            'totalPackets': total_packets,
            'totalBytes': total_bytes,
            'totalFlows': len(flows),
            'encryptedFlowsCount': encrypted_flows,
            'protocolCounts': dict(proto_counts.most_common(20)),
            'serviceCounts': dict(service_counts.most_common(20)),
            'anomaliesSummary': anomalies,
            'rttStats': rtt_stats,
            'findings': findings[:300],
            'tlsSessions': list(tls_sessions.values())[:100],
            'flows': flows_out,
            'auditDisclosure': (
                'Decodificación binaria 100% determinística desde la captura de red. '
                'Los paquetes TLS Application Data contienen carga útil cifrada y nunca se infiere ni inventa contenido HTTP/LDAP interno sin clave privada.'
            ),
            'analyzedAt': time.strftime('%Y-%m-%d %H:%M:%S'),
        }

        cur.execute('INSERT OR REPLACE INTO pcap_meta VALUES (?, ?)', ('summary_json', json.dumps(summary_payload, ensure_ascii=False)))
        conn.commit()
        conn.close()
        os.replace(tmp_db, db_path)
        return summary_payload
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        if os.path.exists(tmp_db):
            try:
                os.remove(tmp_db)
            except Exception:
                pass
        raise


def query_pcap_summary(db_path):
    if not db_path or not os.path.exists(db_path):
        return {'status': 'empty', 'totalPackets': 0}
    conn = sqlite3.connect(db_path, timeout=30.0)
    cur = conn.cursor()
    cur.execute("SELECT value FROM pcap_meta WHERE key='summary_json'")
    row = cur.fetchone()
    conn.close()
    if row and row[0]:
        return json.loads(row[0])
    return {'status': 'empty', 'totalPackets': 0}


def query_pcap_packets(db_path, page=1, limit=100, q='', proto='ALL', severity='ALL', flow=''):
    if not db_path or not os.path.exists(db_path):
        return {'status': 'empty', 'packets': [], 'totalMatching': 0, 'page': 1, 'totalPages': 0}

    page = max(1, int(page))
    limit = min(500, max(10, int(limit)))
    offset = (page - 1) * limit

    conditions = []
    params = []

    if q:
        like_q = f'%{q}%'
        conditions.append('(src_ip LIKE ? OR dst_ip LIKE ? OR info LIKE ? OR app_proto LIKE ? OR CAST(src_port AS TEXT) LIKE ? OR CAST(dst_port AS TEXT) LIKE ?)')
        params.extend([like_q] * 6)
    if proto and proto.upper() != 'ALL':
        conditions.append('(UPPER(proto) = ? OR UPPER(app_proto) LIKE ?)')
        params.extend([proto.upper(), f'%{proto.upper()}%'])
    if severity and severity.upper() != 'ALL':
        conditions.append('UPPER(severity) = ?')
        params.append(severity.upper())
    if flow:
        conditions.append('flow_key = ?')
        params.append(flow)

    where_sql = ('WHERE ' + ' AND '.join(conditions)) if conditions else ''
    conn = sqlite3.connect(db_path, timeout=30.0)
    cur = conn.cursor()
    cur.execute(f'SELECT COUNT(1) FROM pcap_packets {where_sql}', params)
    total_matching = int((cur.fetchone() or [0])[0] or 0)
    total_pages = max(1, (total_matching + limit - 1) // limit) if total_matching > 0 else 0

    cur.execute(
        f'SELECT frame_num, ts_str, src_ip, src_port, dst_ip, dst_port, proto, app_proto, length, tcp_flags, severity, info, is_encrypted, flow_key '
        f'FROM pcap_packets {where_sql} ORDER BY frame_num ASC LIMIT ? OFFSET ?',
        params + [limit, offset],
    )
    rows = cur.fetchall()
    conn.close()

    packets = [{
        'frameNum': r[0],
        'timestamp': r[1],
        'srcIp': r[2],
        'srcPort': r[3],
        'dstIp': r[4],
        'dstPort': r[5],
        'proto': r[6],
        'appProto': r[7],
        'length': r[8],
        'tcpFlags': r[9],
        'severity': r[10],
        'info': r[11],
        'isEncrypted': bool(r[12]),
        'flowKey': r[13],
    } for r in rows]

    return {
        'status': 'ready',
        'packets': packets,
        'totalMatching': total_matching,
        'page': page,
        'limit': limit,
        'totalPages': total_pages,
    }


def _parse_iso_to_epoch(ts_str):
    if not ts_str:
        return None
    m = re.match(r'^(\d{4})[-/](\d{2})[-/](\d{2})[\sT](\d{2}:\d{2}:\d{2})', str(ts_str).strip())
    if not m:
        return None
    try:
        dt = datetime.datetime.strptime(f'{m.group(1)}-{m.group(2)}-{m.group(3)} {m.group(4)}', '%Y-%m-%d %H:%M:%S')
        return dt.timestamp()
    except Exception:
        return None


def correlate_pcap_with_entrust_logs(pcap_db_path, logs_db_path, window_sec=5):
    summary = query_pcap_summary(pcap_db_path)
    if summary.get('status') != 'ready':
        return {'status': 'empty', 'correlations': [], 'message': 'No hay captura PCAP analizada para este cliente.'}
    if not logs_db_path or not os.path.exists(logs_db_path):
        return {'status': 'no_logs', 'correlations': [], 'message': 'No hay base de datos SQLite de logs Entrust activa para correlacionar.'}
    if not summary.get('hasCalendarDate'):
        return {
            'status': 'no_calendar_date',
            'correlations': [],
            'message': 'La captura tcpdump en texto no contiene fecha de calendario (ejecute tcpdump con -tttt o use formato binario .pcap/.pcapng) — no se inventan fechas para correlacionar.',
        }

    net_events = []
    for f in summary.get('findings', []):
        ep = _parse_iso_to_epoch(f.get('timestamp', ''))
        if ep is not None:
            net_events.append((ep, f))
    if not net_events:
        return {'status': 'ready', 'correlations': [], 'totalMatches': 0, 'message': 'La captura no presenta anomalías críticas/advertencias de red con timestamp correlacionable.'}

    min_ep = min(e[0] for e in net_events) - window_sec - 2
    max_ep = max(e[0] for e in net_events) + window_sec + 2
    t_min_str = datetime.datetime.fromtimestamp(min_ep).strftime('%Y-%m-%d %H:%M:%S')
    t_max_str = datetime.datetime.fromtimestamp(max_ep).strftime('%Y-%m-%d %H:%M:%S')

    conn = sqlite3.connect(logs_db_path, timeout=30.0)
    cur = conn.cursor()
    cur.execute('''
        SELECT line_num, event_time, subject_name, event_type, event_outcome, SUBSTR(message, 1, 180), source_ip
        FROM logs
        WHERE (event_outcome LIKE '%FAIL%' OR event_outcome LIKE '%ERR%' OR event_outcome LIKE '%WARN%')
          AND event_time >= ? AND event_time <= ?
        ORDER BY line_num ASC
        LIMIT 2000
    ''', (t_min_str, t_max_str))
    log_rows = cur.fetchall()
    conn.close()

    parsed_logs = []
    for r in log_rows:
        lep = _parse_iso_to_epoch(r[1])
        if lep is not None:
            parsed_logs.append((lep, {
                'lineNum': r[0],
                'timestamp': r[1],
                'user': r[2],
                'code': r[3],
                'outcome': r[4],
                'message': r[5],
                'ip': r[6],
            }))

    correlations = []
    for net_ep, finding in net_events[:150]:
        matched = []
        for lep, log_obj in parsed_logs:
            delta = round(lep - net_ep, 2)
            if abs(delta) <= window_sec:
                matched.append({**log_obj, 'deltaSec': delta})
                if len(matched) >= 5:
                    break
        if matched:
            correlations.append({
                'networkFinding': finding,
                'matchingLogs': matched,
            })
            if len(correlations) >= 60:
                break

    return {
        'status': 'ready',
        'windowSeconds': window_sec,
        'networkWindow': {'start': t_min_str, 'end': t_max_str},
        'totalMatches': len(correlations),
        'correlations': correlations,
    }


def export_pcap_csv(db_path, export_type='anomalies'):
    summary = query_pcap_summary(db_path)
    if summary.get('status') != 'ready':
        raise FileNotFoundError('No hay análisis PCAP disponible.')

    buf = io.StringIO()
    buf.write('\ufeff')
    writer = csv.writer(buf)

    if export_type == 'flows':
        writer.writerow(['FlowKey', 'Proto', 'Servicio', 'Origen', 'Destino', 'Paquetes', 'Bytes', 'RTT_ms', 'RST', 'Retransmisiones', 'SYN_Sin_Resp', 'TLS_Version', 'SNI', 'Cipher', 'Cifrado', 'Alertas_TLS'])
        for f in summary.get('flows', []):
            writer.writerow([
                f['flowKey'], f['proto'], f['service'],
                f"{f['srcIp']}:{f['srcPort']}", f"{f['dstIp']}:{f['dstPort']}",
                f['packets'], f['bytes'], f['rttMs'] if f['rttMs'] is not None else '',
                f['rstCount'], f['retransCount'], 'SI' if f['unansweredSyn'] else 'NO',
                f['tlsVersion'], f['tlsSni'], f['tlsCipher'],
                'SI' if f['isEncrypted'] else 'NO', '; '.join(f.get('tlsAlerts') or []),
            ])
    elif export_type == 'packets':
        conn = sqlite3.connect(db_path, timeout=30.0)
        cur = conn.cursor()
        cur.execute('SELECT frame_num, ts_str, src_ip, src_port, dst_ip, dst_port, proto, app_proto, length, tcp_flags, severity, is_encrypted, info FROM pcap_packets ORDER BY frame_num ASC LIMIT 50000')
        writer.writerow(['Frame', 'Timestamp', 'SrcIP', 'SrcPort', 'DstIP', 'DstPort', 'Proto', 'AppProto', 'Bytes', 'TCP_Flags', 'Severity', 'Encrypted', 'Info'])
        for r in cur.fetchall():
            writer.writerow([r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9], r[10], 'SI' if r[11] else 'NO', r[12]])
        conn.close()
    else:
        writer.writerow(['Frame', 'Timestamp', 'Severidad', 'Categoria', 'Origen', 'Destino', 'Servicio', 'Evidencia', 'FlowKey'])
        for f in summary.get('findings', []):
            writer.writerow([
                f['frameNum'], f['timestamp'], f['severity'], f['category'],
                f['src'], f['dst'], f['service'], f['evidence'], f['flowKey'],
            ])

    return buf.getvalue().encode('utf-8')

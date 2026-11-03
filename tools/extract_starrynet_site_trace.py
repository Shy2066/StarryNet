#!/usr/bin/env python3
"""Extract one timestamp-direction trace from a bounded StarryNet site capture."""
import argparse
import calendar
import csv
import datetime
import hashlib
import json
import math
import struct
from pathlib import Path


PCAP_FORMATS = {
    bytes.fromhex('d4c3b2a1'): ('<', 1_000_000),
    bytes.fromhex('a1b2c3d4'): ('>', 1_000_000),
    bytes.fromhex('4d3cb2a1'): ('<', 1_000_000_000),
    bytes.fromhex('a1b23c4d'): ('>', 1_000_000_000),
}


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(str(path) + '.tmp')
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n',
                         encoding='utf-8')
    temporary.replace(path)


def parse_utc(value):
    if not value:
        return None
    value = value.strip()
    if value.endswith('Z'):
        value = value[:-1] + '+00:00'
    zone_start = max(value.find('+', 10), value.find('-', 10))
    offset_seconds = 0
    if zone_start >= 0:
        zone = value[zone_start:]
        value = value[:zone_start]
        sign = 1 if zone[0] == '+' else -1
        digits = zone[1:].replace(':', '')
        if len(digits) != 4 or not digits.isdigit():
            raise ValueError('invalid UTC offset in timestamp')
        offset_seconds = sign * (int(digits[:2]) * 3600 + int(digits[2:]) * 60)
    parsed = None
    for timestamp_format in ('%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S'):
        try:
            parsed = datetime.datetime.strptime(value, timestamp_format)
            break
        except ValueError:
            pass
    if parsed is None:
        raise ValueError('unsupported UTC timestamp format')
    return calendar.timegm(parsed.timetuple()) + parsed.microsecond / 1000000.0 \
        - offset_seconds


def packet_network_header(frame, linktype):
    if linktype == 1:  # Ethernet
        if len(frame) < 14:
            return None, None
        protocol = struct.unpack('!H', frame[12:14])[0]
        offset = 14
    elif linktype == 113:  # Linux cooked capture v1
        if len(frame) < 16:
            return None, None
        protocol = struct.unpack('!H', frame[14:16])[0]
        offset = 16
    elif linktype == 276:  # Linux cooked capture v2
        if len(frame) < 20:
            return None, None
        protocol = struct.unpack('!H', frame[:2])[0]
        offset = 20
    else:
        raise ValueError('unsupported PCAP linktype {}'.format(linktype))
    if protocol in (0x8100, 0x88a8) and len(frame) >= offset + 4:
        protocol = struct.unpack('!H', frame[offset + 2:offset + 4])[0]
        offset += 4
    return protocol, offset


def read_capture(path):
    data = Path(path).read_bytes()
    if data[:4] not in PCAP_FORMATS:
        raise ValueError('only classic PCAP is supported')
    endian, tick = PCAP_FORMATS[data[:4]]
    major, minor, _zone, _sigfigs, snaplen, linktype = struct.unpack(
        endian + 'HHiiii', data[4:24])
    if (major, minor) != (2, 4):
        raise ValueError('unsupported PCAP version {}.{}'.format(major, minor))
    records = []
    offset = 24
    while offset + 16 <= len(data):
        seconds, fraction, caplen, origlen = struct.unpack(
            endian + 'IIII', data[offset:offset + 16])
        offset += 16
        frame = data[offset:offset + caplen]
        offset += caplen
        if len(frame) != caplen:
            raise ValueError('truncated PCAP record')
        records.append((seconds + fraction / tick, frame, caplen, origlen))
    if offset != len(data):
        raise ValueError('trailing bytes after final PCAP record')
    return data, snaplen, linktype, records


def read_site_packet(frame, linktype):
    protocol, offset = packet_network_header(frame, linktype)
    if protocol != 0x0800 or offset is None:
        return None
    ip = frame[offset:]
    if len(ip) < 20 or ip[0] >> 4 != 4:
        return None
    ip_header_length = (ip[0] & 0x0f) * 4
    if ip_header_length < 20 or len(ip) < ip_header_length:
        raise ValueError('malformed IPv4 header')
    if ip[9] != 6:  # TCP only
        return None
    ip_length = struct.unpack('!H', ip[2:4])[0]
    fragment = struct.unpack('!H', ip[6:8])[0]
    if fragment & 0x3fff:
        return None
    if len(ip) < ip_header_length + 20:
        raise ValueError('truncated TCP header')
    tcp = ip[ip_header_length:]
    source_port, destination_port = struct.unpack('!HH', tcp[:4])
    tcp_header_length = (tcp[12] >> 4) * 4
    if tcp_header_length < 20 or len(tcp) < tcp_header_length:
        raise ValueError('malformed TCP header')
    source_ip = '.'.join(str(part) for part in ip[12:16])
    destination_ip = '.'.join(str(part) for part in ip[16:20])
    sequence, acknowledgement = struct.unpack('!II', tcp[4:12])
    flags = tcp[13]
    payload_length = max(0, min(ip_length - ip_header_length - tcp_header_length,
                                len(ip) - ip_header_length - tcp_header_length))
    return {
        'src_ip': source_ip,
        'src_port': source_port,
        'dst_ip': destination_ip,
        'dst_port': destination_port,
        'ip_length': ip_length,
        'tcp_payload_length': payload_length,
        'tcp_flags': flags,
        'tcp_sequence': sequence,
        'tcp_acknowledgement': acknowledgement,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pcap', required=True)
    parser.add_argument('--client-ip', required=True)
    parser.add_argument('--peer-ip', required=True)
    parser.add_argument('--peer-port', required=True, type=int)
    parser.add_argument('--interface-mtu', type=int, default=1500,
                        help='MTU in bytes of the captured satellite-facing interface')
    parser.add_argument('--window-json', required=True,
                        help='capture and browser navigation markers for this site visit')
    parser.add_argument('--site-summary', required=True,
                        help='Tor Browser summary that proves the requested page loaded')
    parser.add_argument('--output-dir', required=True)
    args = parser.parse_args()
    if args.interface_mtu <= 0:
        parser.error('--interface-mtu must be positive')

    pcap_path = Path(args.pcap).resolve()
    window = json.loads(Path(args.window_json).read_text(encoding='utf-8'))
    site_summary = json.loads(Path(args.site_summary).read_text(encoding='utf-8'))
    visits = site_summary.get('visits') or []
    visit = visits[0] if visits else {}
    browser_window = visit.get('capture_window') or {}
    start_request = window.get('capture_start_request') or {}
    start_ack = window.get('capture_start_ack') or {}
    start_marker = window.get('site_navigation_started') or {}
    complete_marker = window.get('site_navigation_completed') or {}
    stop_request = window.get('capture_stop_request') or {}
    stop_ack = window.get('capture_stop_ack') or {}
    start_request_time = parse_utc(start_request.get('utc'))
    start_ack_time = parse_utc(start_ack.get('tcpdump_ready_utc'))
    start_time = parse_utc(start_marker.get('utc'))
    complete_time = parse_utc(complete_marker.get('utc'))
    stop_time = parse_utc(stop_request.get('utc'))
    stop_ack_time = parse_utc(stop_ack.get('tcpdump_stopped_utc'))
    ordered_markers = bool(
        start_ack.get('ok') is True and start_time is not None and complete_time is not None
        and stop_request.get('request_id') and stop_ack.get('ok') is True
        and start_request.get('request_id')
        and start_ack.get('request_id') == start_request.get('request_id')
        and stop_ack.get('request_id') == stop_request.get('request_id')
        and start_request_time is not None and start_ack_time is not None
        and stop_time is not None and stop_ack_time is not None
        and start_request_time <= start_ack_time <= start_time <= complete_time <= stop_time <= stop_ack_time
        and start_request.get('monotonic', float('inf'))
            <= start_ack.get('tcpdump_ready_monotonic', -1)
        and start_ack.get('tcpdump_ready_monotonic', float('inf'))
            <= start_marker.get('monotonic', -1)
        and complete_marker.get('monotonic', float('inf'))
            <= stop_request.get('monotonic', -1)
        and stop_request.get('monotonic', float('inf'))
            <= stop_ack.get('tcpdump_stopped_monotonic', -1)
    )
    if not ordered_markers:
        raise ValueError('capture and site navigation markers are missing or out of order')

    blob, snaplen, linktype, records = read_capture(pcap_path)
    selected = []
    excluded_before = 0
    excluded_after = 0
    unmatched = 0
    raw_timestamp_reversals = 0
    previous_timestamp = None
    for index, (timestamp, frame, caplen, origlen) in enumerate(records, 1):
        if previous_timestamp is not None and timestamp < previous_timestamp:
            raw_timestamp_reversals += 1
        previous_timestamp = timestamp
        packet = read_site_packet(frame, linktype)
        if packet is None:
            unmatched += 1
            continue
        if packet['src_ip'] == args.client_ip and packet['dst_ip'] == args.peer_ip \
                and packet['dst_port'] == args.peer_port:
            direction = 1
        elif packet['src_ip'] == args.peer_ip and packet['dst_ip'] == args.client_ip \
                and packet['src_port'] == args.peer_port:
            direction = -1
        else:
            unmatched += 1
            continue
        if timestamp < start_time:
            excluded_before += 1
            continue
        if timestamp > stop_time:
            excluded_after += 1
            continue
        packet.update({'pcap_record': index, 'timestamp': timestamp,
                       'direction': direction, 'captured_length': caplen,
                       'original_frame_length': origlen})
        selected.append(packet)
    if not selected:
        raise ValueError('no client-to-GS27 TCP packets fell inside the site navigation window')
    selected.sort(key=lambda packet: (packet['timestamp'], packet['pcap_record']))

    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    trace_path = output_dir / 'trace.tsv'
    packet_path = output_dir / 'packet_audit.csv'
    origin = selected[0]['timestamp']
    with trace_path.open('w', newline='', encoding='utf-8') as stream:
        writer = csv.writer(stream, delimiter='\t', lineterminator='\n')
        for packet in selected:
            writer.writerow(('{:.6f}'.format(packet['timestamp'] - origin),
                             packet['direction']))
    packet_fields = ['pcap_record', 'timestamp_utc', 'time_from_trace_start_s', 'direction',
                     'src_ip', 'src_port', 'dst_ip', 'dst_port', 'ip_total_length',
                     'tcp_payload_length', 'tcp_flags_hex', 'tcp_sequence',
                     'tcp_acknowledgement', 'captured_frame_length', 'original_frame_length']
    with packet_path.open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=packet_fields, lineterminator='\n')
        writer.writeheader()
        for packet in selected:
            timestamp_utc = datetime.datetime.fromtimestamp(
                packet['timestamp'], datetime.timezone.utc).isoformat(
                    timespec='microseconds').replace('+00:00', 'Z')
            writer.writerow({
                'pcap_record': packet['pcap_record'], 'timestamp_utc': timestamp_utc,
                'time_from_trace_start_s': '{:.6f}'.format(packet['timestamp'] - origin),
                'direction': packet['direction'], 'src_ip': packet['src_ip'],
                'src_port': packet['src_port'], 'dst_ip': packet['dst_ip'],
                'dst_port': packet['dst_port'], 'ip_total_length': packet['ip_length'],
                'tcp_payload_length': packet['tcp_payload_length'],
                'tcp_flags_hex': '0x{:02x}'.format(packet['tcp_flags']),
                'tcp_sequence': packet['tcp_sequence'],
                'tcp_acknowledgement': packet['tcp_acknowledgement'],
                'captured_frame_length': packet['captured_length'],
                'original_frame_length': packet['original_frame_length'],
            })

    directions = [packet['direction'] for packet in selected]
    lengths = sorted(packet['ip_length'] for packet in selected)
    flow_counts = {}
    payload_segment_counts = {}
    tcp_control_flags = {'syn': 0, 'fin': 0, 'rst': 0}
    control_only_packets = 0
    for packet in selected:
        flow_key = '{}:{} -> {}:{}'.format(packet['src_ip'], packet['src_port'],
                                           packet['dst_ip'], packet['dst_port'])
        flow_counts[flow_key] = flow_counts.get(flow_key, 0) + 1
        if packet['tcp_payload_length']:
            segment_key = (flow_key, packet['tcp_sequence'], packet['tcp_payload_length'])
            payload_segment_counts[segment_key] = payload_segment_counts.get(segment_key, 0) + 1
        else:
            control_only_packets += 1
        flags = packet['tcp_flags']
        tcp_control_flags['syn'] += int(bool(flags & 0x02))
        tcp_control_flags['fin'] += int(bool(flags & 0x01))
        tcp_control_flags['rst'] += int(bool(flags & 0x04))
    repeated_segment_keys = [key for key, count in payload_segment_counts.items()
                             if count > 1]
    repeated_segment_observations = sum(payload_segment_counts[key] - 1
                                        for key in repeated_segment_keys)
    timestamp_ties = sum(1 for index in range(1, len(selected))
                         if selected[index]['timestamp'] == selected[index - 1]['timestamp'])
    check_seen = bool(browser_window.get('tor_check_stream_seen'))
    both_directions = 1 in directions and -1 in directions
    check_streams_drained = bool(visit.get('check_streams_closed_before_capture'))
    page_passed = bool(visit.get('page_loaded') and visit.get('http_status') == 200
                       and visit.get('target_stream_succeeded') and check_streams_drained)
    result = {
        'status': 'clean_site_window_candidate' if ordered_markers and page_passed
                  and both_directions and not check_seen else 'site_window_trace_needs_review',
        'source_pcap': str(pcap_path),
        'source_pcap_sha256': hashlib.sha256(blob).hexdigest(),
        'source_pcap_bytes': len(blob),
        'source_pcap_records': len(records),
        'pcap_linktype': linktype,
        'pcap_snaplen': snaplen,
        'capture_interface': window.get('capture_interface'),
        'capture_interface_mtu_bytes': args.interface_mtu,
        'trace_path': str(trace_path),
        'trace_sha256': hashlib.sha256(trace_path.read_bytes()).hexdigest(),
        'packet_audit_path': str(packet_path),
        'packet_audit_sha256': hashlib.sha256(packet_path.read_bytes()).hexdigest(),
        'packet_count': len(selected),
        'direction_counts': {'client_to_gs27': directions.count(1),
                             'gs27_to_client': directions.count(-1)},
        'trace_row_count': len(selected),
        'tcp_flow_count': len(flow_counts),
        'tcp_flow_packet_counts': flow_counts,
        'window_start_utc': datetime.datetime.fromtimestamp(
            start_time, datetime.timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z'),
        'window_end_utc': datetime.datetime.fromtimestamp(
            stop_time, datetime.timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z'),
        'window_duration_seconds': round(stop_time - start_time, 6),
        'excluded_packets_before_navigation': excluded_before,
        'excluded_packets_after_stop_request': excluded_after,
        'unmatched_or_non_tcp_packets': unmatched,
        'raw_pcap_timestamp_reversals': raw_timestamp_reversals,
        'equal_timestamp_adjacent_rows': timestamp_ties,
        'packet_quality': {
            'tcp_payload_packets': len(selected) - control_only_packets,
            'tcp_ack_or_control_only_packets': control_only_packets,
            'repeated_payload_segment_keys': len(repeated_segment_keys),
            'extra_observations_of_repeated_payload_segments': repeated_segment_observations,
            'tcp_syn_records': tcp_control_flags['syn'],
            'tcp_fin_records': tcp_control_flags['fin'],
            'tcp_rst_records': tcp_control_flags['rst'],
        },
        'ip_length_bytes': {
            'min': lengths[0], 'median': (lengths[(len(lengths)-1)//2] + lengths[len(lengths)//2]) / 2,
            'p95': lengths[math.ceil(.95 * len(lengths)) - 1], 'max': lengths[-1],
            'over_interface_mtu_count': sum(length > args.interface_mtu for length in lengths),
        },
        'window_markers_verified': ordered_markers,
        'capture_start_request_acknowledged': bool(start_request.get('request_id')
            and start_ack.get('request_id') == start_request.get('request_id')),
        'capture_stop_request_acknowledged': bool(stop_request.get('request_id')
            and stop_ack.get('request_id') == stop_request.get('request_id')),
        'page_http_200_and_tor_stream_verified': page_passed,
        'target_stream_evidence_source': visit.get(
            'target_stream_evidence_source', 'measured_visit_stream'),
        'target_stream_observed_during_capture': (
            visit.get('target_stream_evidence_source', 'measured_visit_stream')
            == 'measured_visit_stream'),
        'tor_check_streams_closed_before_capture': check_streams_drained,
        'check_page_stream_seen_during_navigation': check_seen,
        'bidirectional': both_directions,
        'resource_origins': visit.get('resource_origins', []),
        'tor_stream_domains_during_site_navigation': browser_window.get('site_stream_domains', []),
        'scientific_fidelity_verified': False,
    }
    audit_path = output_dir / 'AUDIT.md'
    audit_lines = [
        '# Site-window trace audit',
        '',
        '- Status: `{}`'.format(result['status']),
        '- Source PCAP SHA-256: `{}`'.format(result['source_pcap_sha256']),
        '- Window: {} to {} ({} s)'.format(
            result['window_start_utc'], result['window_end_utc'],
            result['window_duration_seconds']),
        '- Trace rows: {}; directions: client→GS27 `{}`, GS27→client `{}`.'.format(
            result['trace_row_count'], result['direction_counts']['client_to_gs27'],
            result['direction_counts']['gs27_to_client']),
        '- TCP flows: {}; flow packet counts: `{}`.'.format(
            result['tcp_flow_count'], json.dumps(result['tcp_flow_packet_counts'],
                                                 sort_keys=True)),
        '- Capture markers verified: {}; page HTTP 200 and target-stream evidence verified: {} (source: `{}`).'.format(
            ordered_markers, page_passed, result['target_stream_evidence_source']),
        '- Tor check streams closed before capture: `{}`.'.format(check_streams_drained),
        '- Tor check stream observed during navigation: `{}`.'.format(check_seen),
        '- Tor STREAM domains during navigation: `{}`.'.format(
            ', '.join(result['tor_stream_domains_during_site_navigation']) or '(none recorded)'),
        '- Resource origins reported by the browser: `{}`.'.format(
            ', '.join(result['resource_origins']) or '(none recorded)'),
        '- Packets excluded before navigation / after stop request: {} / {}.'.format(
            excluded_before, excluded_after),
        '- Raw PCAP timestamp reversals: {}; adjacent equal-time trace rows: {}.'.format(
            raw_timestamp_reversals, timestamp_ties),
        '- IP lengths in bytes: min {}, median {}, p95 {}, max {}; above interface MTU ({} bytes): {}.'.format(
            lengths[0], result['ip_length_bytes']['median'],
            result['ip_length_bytes']['p95'], lengths[-1],
            args.interface_mtu, result['ip_length_bytes']['over_interface_mtu_count']),
        '- TCP payload packets: {}; ACK/control-only packets: {}; repeated payload segment keys: {}; extra observations: {}.'.format(
            result['packet_quality']['tcp_payload_packets'],
            result['packet_quality']['tcp_ack_or_control_only_packets'],
            result['packet_quality']['repeated_payload_segment_keys'],
            result['packet_quality']['extra_observations_of_repeated_payload_segments']),
        '- TCP SYN / FIN / RST records: {} / {} / {}.'.format(
            result['packet_quality']['tcp_syn_records'],
            result['packet_quality']['tcp_fin_records'],
            result['packet_quality']['tcp_rst_records']),
        '',
        'The trace is the GS26-to-GS27 encrypted Tor WebTunnel transport observed during one browser navigation window. It includes transport packets for the page and its browser-loaded resources; it does not expose destination-site TCP packets or prove scientific fidelity. Packet lengths above the observed interface MTU require offload-aware interpretation. This artifact is a trace candidate, not a dataset sample.',
        '',
    ]
    audit_path.write_text('\n'.join(audit_lines), encoding='utf-8')
    result['audit_path'] = str(audit_path)
    result['audit_sha256'] = hashlib.sha256(audit_path.read_bytes()).hexdigest()
    manifest_path = output_dir / 'manifest.json'
    write_json(manifest_path, result)
    result['manifest_path'] = str(manifest_path)
    print(json.dumps(result, sort_keys=True))
    return 0 if ordered_markers and page_passed and both_directions and not check_seen else 2


if __name__ == '__main__':
    raise SystemExit(main())

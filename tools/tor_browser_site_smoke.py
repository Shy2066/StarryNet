#!/usr/bin/env python3
"""Bounded Tor Browser site-access smoke for one paper-mapped class."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time
from urllib.parse import urlsplit


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(str(path) + '.tmp')
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    temporary.replace(path)


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds')


def capture_marker(control_dir, name, **extra):
    marker = {'name': name, 'utc': utc_now(), 'monotonic': time.monotonic()}
    marker.update(extra)
    if control_dir:
        write_json(Path(control_dir) / (name + '.json'), marker)
    return marker


def request_capture_control(control_dir, phase, timeout, visit_index):
    request_id = '{}-{}'.format(os.getpid(), time.monotonic_ns())
    ack_path = Path(control_dir) / 'capture_{}_ack.json'.format(phase)
    ack_path.unlink(missing_ok=True)
    request = capture_marker(control_dir, 'capture_{}_request'.format(phase),
                             request_id=request_id, visit_index=visit_index)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if ack_path.is_file():
            ack = json.loads(ack_path.read_text(encoding='utf-8'))
            if ack.get('request_id') != request_id:
                raise RuntimeError('capture {} acknowledgement ID mismatch'.format(phase))
            if not ack.get('ok'):
                raise RuntimeError('capture {} failed: {}'.format(
                    phase, ack.get('error', 'unknown host error')))
            return request, ack
        time.sleep(0.05)
    raise TimeoutError('host did not acknowledge capture {}'.format(phase))


def close_target_site_storage(driver):
    driver.execute_script(
        'try { localStorage.clear(); sessionStorage.clear(); } catch (e) {}')
    driver.delete_all_cookies()
    driver.get('about:blank')
    return (driver.current_url or '').lower() == 'about:blank'


def clear_site_state(driver):
    driver.execute_script(
        'try { localStorage.clear(); sessionStorage.clear(); } catch (e) {}')
    driver.delete_all_cookies()


def browser_resource_timing_snapshot(driver):
    """Capture comparable resource timings without retaining full URLs."""
    try:
        snapshot = driver.execute_script(
            'const n=performance.getEntriesByType("navigation")[0];'
            'const r=performance.getEntriesByType("resource");'
            'return {ready_state:document.readyState,resource_count:r.length,'
            'navigation:n?{type:n.type,duration:n.duration,'
            'dom_content_loaded:n.domContentLoadedEventEnd,'
            'load_event_end:n.loadEventEnd}:null,'
            'resources:r.map(e=>({name:e.name,initiator_type:e.initiatorType,'
            'start_time:e.startTime,duration:e.duration,fetch_start:e.fetchStart,'
            'request_start:e.requestStart,response_start:e.responseStart,'
            'response_end:e.responseEnd,transfer_size:e.transferSize,'
            'encoded_body_size:e.encodedBodySize,decoded_body_size:e.decodedBodySize,'
            'next_hop_protocol:e.nextHopProtocol}))};')
    except Exception as exc:
        return {'available': False,
                'error': type(exc).__name__ + ': ' + str(exc)[:200],
                'captured_monotonic': time.monotonic()}

    resources = []
    for entry in snapshot.get('resources', []):
        raw_name = str(entry.pop('name', ''))
        parsed = urlsplit(raw_name)
        canonical_name = '{}://{}{}'.format(
            parsed.scheme.lower(), parsed.netloc.lower(), parsed.path)
        entry['resource_key'] = hashlib.sha256(
            canonical_name.encode('utf-8', errors='replace')).hexdigest()[:20]
        entry['origin'] = '{}://{}'.format(
            parsed.scheme.lower(), parsed.netloc.lower()) if parsed.netloc else parsed.scheme
        resources.append(entry)
    snapshot['resources'] = resources
    snapshot['available'] = True
    snapshot['captured_monotonic'] = time.monotonic()
    return snapshot


def perform_tor_check(driver, controller, check_stream_ids,
                      check_stream_events, args):
    check_ids_before_visit = set(check_stream_ids)
    evidence = {'tor_check_started_monotonic': time.monotonic()}
    driver.get('https://check.torproject.org/api/ip')
    evidence['tor_check_completed_monotonic'] = time.monotonic()
    visit_check_ids = set(check_stream_ids) - check_ids_before_visit
    visit_check_events = [event for event in check_stream_events
                          if event['id'] in visit_check_ids]
    evidence['check_stream_succeeded'] = any(
        event['status'] == 'SUCCEEDED' for event in visit_check_events)
    evidence['check_stream_circuit_ids'] = sorted({event['circuit_id']
        for event in visit_check_events if event['status'] == 'SUCCEEDED'})
    evidence['check_stream_statuses'] = [event['status']
                                        for event in visit_check_events]
    check_page = driver.execute_script(
        'const n=performance.getEntriesByType("navigation")[0];'
        'return {url:location.href,title:document.title,ready:document.readyState,'
        'status:n&&typeof n.responseStatus==="number"?n.responseStatus:null,'
        'text:(document.body&&document.body.innerText||"").slice(0,300)};')
    match = re.search(r'\bIsTor\s+(true|false)\b', check_page.get('text', ''), re.I)
    check_is_tor = bool(match and match.group(1).lower() == 'true')
    evidence['tor_check_passed'] = (
        check_is_tor and evidence['check_stream_succeeded'])
    evidence['tor_check_response'] = {
        'is_tor': check_is_tor if match else None,
        'http_status': check_page.get('status'),
        'has_exit_ip': bool(re.search(
            r'\bIP\s+["\']?\d+\.\d+\.\d+\.\d+',
            check_page.get('text', ''))),
    }
    check_page['text'] = re.sub(
        r'\b\d{1,3}(?:\.\d{1,3}){3}\b', '[redacted IP]',
        check_page.get('text', ''))
    evidence['check_page'] = check_page
    evidence['socks_prefs'] = {key: driver.options.preferences.get(key)
        for key in ('network.proxy.type', 'network.proxy.socks',
                    'network.proxy.socks_port', 'network.proxy.socks_version',
                    'network.proxy.socks_remote_dns', 'network.proxy.no_proxies_on',
                    'network.proxy.failover_direct')}
    if not evidence['tor_check_passed']:
        raise RuntimeError('Tor Browser check did not return IsTor=true')

    if args.capture_control_dir:
        if not visit_check_ids:
            raise RuntimeError('Tor check produced no identifiable STREAM IDs')
        driver.get('about:blank')
        evidence['check_page_closed_before_capture'] = (
            (driver.current_url or '').lower() == 'about:blank')
        if not evidence['check_page_closed_before_capture']:
            raise RuntimeError('could not leave the Tor check page before capture')
        drain_started = time.monotonic()
        drain_deadline = drain_started + 3
        terminal_statuses = {'CLOSED', 'DETACHED', 'FAILED'}
        while time.monotonic() < drain_deadline:
            closed_ids = {event['id'] for event in check_stream_events
                          if event['status'] in terminal_statuses}
            if visit_check_ids and visit_check_ids.issubset(closed_ids):
                break
            time.sleep(0.05)
        closed_ids = {event['id'] for event in check_stream_events
                      if event['status'] in terminal_statuses}
        close_actions = []
        for stream_id in sorted(visit_check_ids - closed_ids):
            try:
                controller.close_stream(stream_id)
                close_actions.append({'stream_id': stream_id,
                                      'result': 'close_requested'})
            except Exception as exc:
                close_actions.append({'stream_id': stream_id,
                    'result': 'close_request_failed',
                    'error': type(exc).__name__ + ': ' + str(exc)[:200]})
        close_deadline = time.monotonic() + 5
        while time.monotonic() < close_deadline:
            closed_ids = {event['id'] for event in check_stream_events
                          if event['status'] in terminal_statuses}
            if visit_check_ids.issubset(closed_ids):
                break
            time.sleep(0.05)
        closed_ids = {event['id'] for event in check_stream_events
                      if event['status'] in terminal_statuses}
        evidence['check_stream_ids'] = sorted(visit_check_ids)
        evidence['check_stream_close_actions'] = close_actions
        evidence['check_streams_closed_before_capture'] = (
            visit_check_ids.issubset(closed_ids))
        evidence['check_stream_close_wait_seconds'] = round(
            time.monotonic() - drain_started, 6)
        if not evidence['check_streams_closed_before_capture']:
            raise TimeoutError(
                'Tor check streams remained open after controller close requests: '
                + ','.join(sorted(visit_check_ids - closed_ids)))
    return evidence


def free_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def wait_for_page_content(driver, timeout_seconds, idle_seconds,
                          require_resource_idle=True):
    """Wait for visible page text and a quiet Performance resource list."""
    started = time.monotonic()
    deadline = started + timeout_seconds
    last_resource_count = None
    idle_since = None
    page = {}
    while True:
        page = driver.execute_script(
            'const n=performance.getEntriesByType("navigation")[0];'
            'const r=performance.getEntriesByType("resource");'
            'const origins=[...new Set(r.map(e=>{try{return new URL(e.name).origin}'
            'catch(_){return null}}).filter(Boolean))].sort();'
            'const text=(document.body&&document.body.innerText||"").trim();'
            'return {url:location.href,title:document.title,ready:document.readyState,'
            'domain:document.domain,status:n&&typeof n.responseStatus==="number"?n.responseStatus:null,'
            'text:text.slice(0,240),text_length:text.length,resource_count:r.length,'
            'resource_origins:origins};')
        now = time.monotonic()
        resource_count = page.get('resource_count', 0)
        content_ready = (page.get('ready') == 'complete'
                         and bool(page.get('title'))
                         and page.get('text_length', 0) >= 40)
        if content_ready:
            if not require_resource_idle:
                return page, False, round(now - started, 3)
            if resource_count != last_resource_count:
                last_resource_count = resource_count
                idle_since = now
            elif idle_since is None:
                idle_since = now
            elif now - idle_since >= idle_seconds:
                return page, True, round(now - started, 3)
        else:
            last_resource_count = resource_count
            idle_since = None
        if now >= deadline:
            return page, False, round(now - started, 3)
        time.sleep(0.5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--browser-dir', required=True,
        help='Tor Browser folder containing Browser/')
    parser.add_argument('--expert-bundle', required=True,
        help='Verified Tor Expert Bundle directory')
    parser.add_argument('--bridge-file', required=True,
        help='Official WebTunnel bridge lines; kept out of the result summary')
    parser.add_argument('--geckodriver', required=True,
        help='Mozilla geckodriver binary')
    parser.add_argument('--output-root', default='artifacts/tor_browser_site_smoke')
    parser.add_argument('--url', default='https://www.adobe.com/')
    parser.add_argument('--label', default='0')
    parser.add_argument('--visits', type=int, default=3)
    parser.add_argument('--bootstrap-timeout', type=int, default=300)
    parser.add_argument('--page-load-timeout', type=int, default=240,
        help='maximum seconds to wait for each page navigation')
    parser.add_argument('--page-content-timeout', type=int, default=60,
        help='maximum seconds to wait for visible page text and resource-idle')
    parser.add_argument('--resource-idle-seconds', type=float, default=4.0,
        help='resource timing entry count must remain unchanged this long')
    parser.add_argument('--reuse-check-circuit-for-first-site', action='store_true',
        help='use the Tor circuit already verified by the check page for visit 1')
    parser.add_argument('--reuse-circuit-between-visits', action='store_true',
        help='do not request NEWNYM between fresh browser profiles')
    parser.add_argument('--reuse-browser-profile-between-visits', action='store_true',
        help='reuse one writable Tor Browser profile across visits')
    parser.add_argument('--reuse-browser-process-between-visits', action='store_true',
        help='keep one Tor Browser process alive for the full visit series')
    parser.add_argument('--enable-browser-cache-between-visits', action='store_true',
        help='retain Firefox HTTP cache from the uncaptured warm-up across same-tab refreshes')
    parser.add_argument('--pin-tor-middle-fingerprint',
        help='V26 lab diagnostic: pin Tor MiddleNodes to this 40-hex relay fingerprint')
    parser.add_argument('--pin-tor-exit-fingerprint',
        help='V26 lab diagnostic: pin Tor ExitNodes to this 40-hex relay fingerprint')
    parser.add_argument('--fixed-window-seconds', type=int,
        help='end each capture at this many seconds after target navigation starts')
    parser.add_argument('--warmup-site-visit', action='store_true',
        help='visit the target without capture before measured access')
    parser.add_argument('--warmup-before-each-visit', action='store_true',
        help='perform the same uncaptured target warm-up before every measured visit')
    parser.add_argument('--reuse-target-page-between-visits', action='store_true',
        help='perform one Tor check and uncaptured warm-up, then same-tab refresh captures')
    parser.add_argument('--warmup-settle-seconds', type=float, default=10.0,
        help='keep the uncaptured warm-up page open after visible content is ready')
    parser.add_argument('--capture-control-dir',
        help='shared directory used to bracket one site navigation with the network capture')
    parser.add_argument('--capture-ack-timeout', type=int, default=60)
    parser.add_argument('--capture-settle-seconds', type=float, default=2.0)
    args = parser.parse_args()
    if bool(args.pin_tor_middle_fingerprint) != bool(args.pin_tor_exit_fingerprint):
        parser.error('V26 Tor path diagnostic requires both middle and exit fingerprints')
    if args.pin_tor_middle_fingerprint:
        for name in ('pin_tor_middle_fingerprint', 'pin_tor_exit_fingerprint'):
            value = getattr(args, name).strip()
            if not re.fullmatch(r'[0-9A-Fa-f]{40}', value):
                parser.error(name.replace('_', '-') + ' must be exactly 40 hexadecimal characters')
            setattr(args, name, value.upper())
        if not (args.visits == 1 and args.fixed_window_seconds == 85
                and args.warmup_site_visit and not args.warmup_before_each_visit
                and args.reuse_target_page_between_visits
                and args.reuse_check_circuit_for_first_site
                and args.enable_browser_cache_between_visits):
            parser.error('V26 Tor path pinning is limited to the one-visit cache-on matched-phase refresh protocol')
    if not 1 <= args.visits <= 3:
        parser.error('this diagnostic is limited to 1–3 visits')
    if args.reuse_browser_process_between_visits and not (
            args.reuse_browser_profile_between_visits):
        parser.error('reusing the browser process requires reusing its profile')
    if not 15 <= args.page_load_timeout <= 300:
        parser.error('page load timeout must be between 15 and 300 seconds')
    if not 15 <= args.page_content_timeout <= 120:
        parser.error('page content timeout must be between 15 and 120 seconds')
    if not 1 <= args.resource_idle_seconds <= 15:
        parser.error('resource idle interval must be between 1 and 15 seconds')
    if not 0 <= args.capture_settle_seconds <= 15:
        parser.error('capture settle interval must be between 0 and 15 seconds')
    if args.fixed_window_seconds is not None and not 30 <= args.fixed_window_seconds <= 300:
        parser.error('fixed capture window must be between 30 and 300 seconds')
    if not 0 <= args.warmup_settle_seconds <= 60:
        parser.error('warm-up settle interval must be between 0 and 60 seconds')
    if (args.warmup_site_visit or args.warmup_before_each_visit) and not (
            args.capture_control_dir and args.fixed_window_seconds is not None
            and ((args.visits == 3
                  and args.reuse_browser_profile_between_visits
                  and args.reuse_browser_process_between_visits)
                 or (args.visits == 1
                     and args.reuse_target_page_between_visits))):
        parser.error('site warm-up requires capture control and either three persistent-profile visits or one matched-phase visit')
    if args.reuse_target_page_between_visits and not (
            args.capture_control_dir and args.fixed_window_seconds is not None
            and args.warmup_site_visit and not args.warmup_before_each_visit
            and args.reuse_check_circuit_for_first_site
            and ((args.visits == 3
                  and args.reuse_browser_profile_between_visits
                  and args.reuse_browser_process_between_visits
                  and args.reuse_circuit_between_visits)
                 or args.visits == 1)):
        parser.error('--reuse-target-page-between-visits requires one initial check/warm-up and either three persistent-profile visits or one single-visit run')
    if args.enable_browser_cache_between_visits and not (
            args.reuse_target_page_between_visits
            and (args.visits == 1 or (
                args.reuse_browser_profile_between_visits
                and args.reuse_browser_process_between_visits))):
        parser.error('--enable-browser-cache-between-visits requires a same-page refresh; multi-visit series also requires a persistent browser profile and process')
    parsed = urlsplit(args.url)
    if parsed.scheme != 'https' or not parsed.hostname:
        parser.error('site URL must be HTTPS')

    browser_dir = Path(args.browser_dir).resolve()
    bundle = Path(args.expert_bundle).resolve()
    bridge_file = Path(args.bridge_file).resolve()
    geckodriver = Path(args.geckodriver).resolve()
    tbb_driver = browser_dir / 'Browser' / 'firefox'
    tor = bundle / 'tor' / 'tor'
    lyrebird = bundle / 'tor' / 'pluggable_transports' / 'lyrebird'
    for path in (tbb_driver, tor, lyrebird,
                 bundle / 'data' / 'geoip', bundle / 'data' / 'geoip6'):
        if not path.is_file():
            parser.error('required signed bundle file is missing: ' + str(path))
    if not bridge_file.is_file():
        parser.error('bridge file is missing')
    if not geckodriver.is_file():
        parser.error('geckodriver binary is missing')
    bridge_lines = [line.strip() for line in bridge_file.read_text().splitlines()
                    if line.strip() and not line.lstrip().startswith('#')]
    bridge_lines = [line[7:] if line.startswith('Bridge ') else line
                    for line in bridge_lines]
    if not bridge_lines or any(not line.startswith('webtunnel ') for line in bridge_lines):
        parser.error('the provided bridge file must contain WebTunnel lines')

    proxy_text = os.environ.get('https_proxy') or os.environ.get('HTTPS_PROXY') or ''
    proxy = urlsplit(proxy_text)
    if (proxy.scheme != 'http' or proxy.hostname != '127.0.0.1'
            or not proxy.port or proxy.username or proxy.password):
        parser.error('an existing unauthenticated loopback HTTPS_PROXY is required')

    repo = Path(__file__).resolve().parents[1]
    output_root = Path(args.output_root)
    if not output_root.is_absolute():
        output_root = repo / output_root
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S_%fZ')
    run_dir = output_root / stamp
    run_dir.mkdir(parents=True)
    shutil.copyfile(str(Path(__file__).resolve()), str(run_dir / 'tor_browser_site_smoke.py'))
    source_hash = hashlib.sha256((run_dir / 'tor_browser_site_smoke.py').read_bytes()).hexdigest()
    bridge_hash = hashlib.sha256(bridge_file.read_bytes()).hexdigest()
    summary = {
        'run_id': stamp,
        'label': str(args.label),
        'requested_url': args.url,
        'site_host': parsed.hostname,
        'browser': 'official Tor Browser; Selenium via tbselenium; headless',
        'transport': 'WebTunnel over existing loopback HTTP proxy',
        'visit_limit': args.visits,
        'fresh_browser_profile_each_visit': not args.reuse_browser_profile_between_visits,
        'persistent_browser_profile_across_visits': args.reuse_browser_profile_between_visits,
        'browser_cache_enabled_between_visits': args.enable_browser_cache_between_visits,
        'newnym_before_subsequent_site_visits': not args.reuse_circuit_between_visits,
        'reuse_circuit_between_visits_requested': args.reuse_circuit_between_visits,
        'newnym_after_check_before_first_site_visit':
            not args.reuse_check_circuit_for_first_site,
        'reuse_check_circuit_for_first_site': args.reuse_check_circuit_for_first_site,
        'reuse_target_page_between_visits': args.reuse_target_page_between_visits,
        'tor_path_constraints': ({
            'mode': 'fixed_middle_exit_diagnostic',
            'middle_fingerprint': args.pin_tor_middle_fingerprint,
            'exit_fingerprint': args.pin_tor_exit_fingerprint,
            'torrc_options': [
                'MiddleNodes ${}'.format(args.pin_tor_middle_fingerprint),
                'ExitNodes ${}'.format(args.pin_tor_exit_fingerprint),
            ],
            'torrc_configuration_verified': False,
        } if args.pin_tor_middle_fingerprint else None),
        'bridge_count': len(bridge_lines),
        'bridge_configuration_sha256': bridge_hash,
        'source_sha256': source_hash,
        'bootstrap_timeout_seconds': args.bootstrap_timeout,
        'page_load_timeout_seconds': args.page_load_timeout,
        'page_content_timeout_seconds': args.page_content_timeout,
        'resource_idle_seconds': args.resource_idle_seconds,
        'capture_settle_seconds': args.capture_settle_seconds,
        'fixed_window_seconds': args.fixed_window_seconds,
        'resource_idle_required_for_readiness': args.fixed_window_seconds is None,
        'webdriver_request_timeout_seconds': args.page_load_timeout + 60,
        'satellite_emulation_used': False,
        'satellite_observation_point_used': False,
        'pcap_generated': False,
        'capture_window_mode': ('site_navigation_only' if args.capture_control_dir else 'disabled'),
        'scientific_fidelity_verified': False,
        'visits': [],
        'site_warmups': [],
        'initial_tor_check': None,
        'errors': [],
        'cleanup_verified': False,
        'passed': False,
    }
    browser_version = (browser_dir / 'Browser' / 'application.ini').read_text(
        errors='replace') if (browser_dir / 'Browser' / 'application.ini').is_file() else ''
    for line in browser_version.splitlines():
        if line.startswith('Version='):
            summary['tor_browser_version'] = line.split('=', 1)[1]
            break
    tor_env = dict(os.environ)
    tor_env['LD_LIBRARY_PATH'] = str(bundle / 'tor')
    try:
        summary['tor_version'] = subprocess.check_output(
            [str(tor), '--version'], env=tor_env, stderr=subprocess.STDOUT,
            universal_newlines=True, timeout=15).splitlines()[0]
        summary['lyrebird_version'] = subprocess.check_output(
            [str(lyrebird), '-version'], env=tor_env, stderr=subprocess.STDOUT,
            universal_newlines=True, timeout=15).splitlines()[0]
        summary['tor_browser_firefox_version'] = subprocess.check_output(
            [str(tbb_driver), '--version'], env=tor_env, stderr=subprocess.STDOUT,
            universal_newlines=True, timeout=15).strip().splitlines()[-1]
        summary['geckodriver_version'] = subprocess.check_output(
            [str(geckodriver), '--version'], stderr=subprocess.STDOUT,
            universal_newlines=True, timeout=15).splitlines()[0]
        import selenium
        import stem
        import tbselenium
        from stem.control import Controller, EventType
        from stem import Signal
        from tbselenium import common as cm
        from tbselenium.tbdriver import TorBrowserDriver
        persistent_profile = None
        if args.reuse_browser_profile_between_visits:
            default_profile = browser_dir / cm.DEFAULT_TBB_PROFILE_PATH
            if not default_profile.is_dir():
                raise RuntimeError('Tor Browser default profile directory is missing')
            persistent_profile = run_dir / 'persistent-profile'
            shutil.copytree(default_profile, persistent_profile,
                ignore=shutil.ignore_patterns('parent.lock', 'lock', '*.lock'))
            summary['persistent_browser_profile_path'] = str(persistent_profile)
        summary['python_package_versions'] = {
            'selenium': selenium.__version__, 'stem': stem.__version__,
            'tbselenium': tbselenium.__version__ if hasattr(tbselenium, '__version__')
                else '0.9.0'}

        socks_port, control_port = free_port(), free_port()
        while control_port == socks_port:
            control_port = free_port()
        private_runtime = Path(tempfile.mkdtemp(prefix='tor-browser-site-smoke-'))
        tor_data = private_runtime / 'tor-data'
        tor_data.mkdir(mode=0o700)
        tor_log = run_dir / 'tor.log'
        tor_process_log = (run_dir / 'tor-process.log').open('w')
        torrc = private_runtime / 'torrc'
        tor_path_lines = []
        if args.pin_tor_middle_fingerprint:
            tor_path_lines = [
                'MiddleNodes ${}'.format(args.pin_tor_middle_fingerprint),
                'ExitNodes ${}'.format(args.pin_tor_exit_fingerprint),
            ]
        torrc_lines = [
            'HTTPSProxy 127.0.0.1:{}'.format(proxy.port),
            'UseBridges 1',
            'ClientTransportPlugin webtunnel exec {} -enableLogging -logLevel INFO'.format(lyrebird),
            'GeoIPFile {}'.format(bundle / 'data' / 'geoip'),
            'GeoIPv6File {}'.format(bundle / 'data' / 'geoip6'),
        ] + tor_path_lines + ['Bridge ' + line for line in bridge_lines]
        torrc.write_text('\n'.join(torrc_lines) + '\n')
        torrc.chmod(0o600)
        if args.pin_tor_middle_fingerprint:
            config_check = subprocess.run(
                [str(tor), '-f', str(torrc), '--verify-config'],
                env=tor_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                universal_newlines=True, timeout=15)
            if config_check.returncode != 0:
                raise RuntimeError(
                    'Tor rejected the V26 path-pinning configuration (exit {}): {}'.format(
                        config_check.returncode,
                        ' '.join(config_check.stdout.split())[-500:]))
            summary['tor_path_constraints']['torrc_configuration_verified'] = True
            write_json(run_dir / 'summary.json', summary)
        tor_process = subprocess.Popen([
            str(tor), '-f', str(torrc), '--DataDirectory', str(tor_data),
            '--ClientOnly', '1', '--SocksPort', '127.0.0.1:{}'.format(socks_port),
            '--ControlPort', '127.0.0.1:{}'.format(control_port),
            '--CookieAuthentication', '1', '--Log', 'notice file {}'.format(tor_log),
        ], env=tor_env, stdout=tor_process_log, stderr=subprocess.STDOUT)
        summary['local_ports'] = {'socks': socks_port, 'control': control_port}
        write_json(run_dir / 'summary.json', summary)

        deadline = time.monotonic() + args.bootstrap_timeout
        last_progress = None
        while time.monotonic() < deadline:
            if tor_process.poll() is not None:
                raise RuntimeError('Tor exited before bootstrap; see tor-process.log')
            content = tor_log.read_text(errors='replace') if tor_log.exists() else ''
            progress = [line for line in content.splitlines() if 'Bootstrapped ' in line]
            if progress and progress[-1] != last_progress:
                last_progress = progress[-1]
                summary['last_bootstrap_message'] = last_progress
                write_json(run_dir / 'summary.json', summary)
            if 'Bootstrapped 100%' in content:
                summary['public_tor_bootstrapped'] = True
                break
            time.sleep(1)
        if not summary.get('public_tor_bootstrapped'):
            raise RuntimeError('Tor bridge bootstrap exceeded the bounded timeout')

        events = []
        circuit_events = []
        check_stream_ids = set()
        check_stream_events = []
        def collect_stream(event):
            record = {
                'id': str(getattr(event, 'id', '')),
                'status': str(getattr(event, 'status', '')),
                'circuit_id': str(getattr(event, 'circ_id', '')),
                'address': str(getattr(event, 'target_address', '')),
                'port': str(getattr(event, 'target_port', '')),
                'reason': str(getattr(event, 'reason', '') or ''),
                'observed_utc': utc_now(),
                'observed_monotonic': time.monotonic(),
            }
            events.append(record)
            address = record['address'].lower().rstrip('.')
            if (record['status'] in ('NEW', 'SENTCONNECT')
                    and address == 'check.torproject.org'):
                check_stream_ids.add(record['id'])
            if record['id'] in check_stream_ids:
                check_stream_events.append({key: value for key, value in record.items()
                    if key != 'address' or value.lower().rstrip('.') == 'check.torproject.org'})

        def collect_circuit(event):
            path = []
            for hop in (getattr(event, 'path', ()) or ()):
                if isinstance(hop, (tuple, list)):
                    fingerprint = hop[0] if hop else None
                    nickname = hop[1] if len(hop) > 1 else None
                else:
                    fingerprint = hop
                    nickname = None
                path.append({
                    'fingerprint': str(fingerprint) if fingerprint else None,
                    'nickname': str(nickname) if nickname else None,
                })
            circuit_events.append({
                'circuit_id': str(getattr(event, 'id', '')),
                'status': str(getattr(event, 'status', '')),
                'path': path,
                'purpose': str(getattr(event, 'purpose', '') or ''),
                'build_flags': list(getattr(event, 'build_flags', ()) or ()),
                'reason': str(getattr(event, 'reason', '') or ''),
                'observed_utc': utc_now(),
                'observed_monotonic': time.monotonic(),
            })

        controller = Controller.from_port(port=control_port)
        controller.authenticate()
        controller.add_event_listener(collect_stream, EventType.STREAM)
        controller.add_event_listener(collect_circuit, EventType.CIRC)
        summary['browser_started'] = True
        write_json(run_dir / 'summary.json', summary)

        browser_driver = None
        for index in range(args.visits):
            result = {
                'attempt': index + 1,
                'fresh_profile': not args.reuse_browser_profile_between_visits,
                'persistent_profile_across_visits':
                    args.reuse_browser_profile_between_visits,
                'browser_process_reused_for_series':
                    args.reuse_browser_process_between_visits,
                'tor_check_passed': False,
                'target_stream_succeeded': False,
                'page_loaded': False,
                'http_status': None,
                'passed': False,
                'errors': [],
            }
            if index and not args.reuse_circuit_between_visits:
                wait = controller.get_newnym_wait()
                if wait > 0:
                    time.sleep(wait)
                controller.signal(Signal.NEWNYM)
            browser_log_path = run_dir / 'browser-visit-{}.log'.format(index + 1)
            driver = (browser_driver if args.reuse_browser_process_between_visits
                      else None)
            start = time.monotonic()
            try:
                driver_kwargs = {
                    'tor_cfg': cm.USE_STEM,
                    'socks_port': socks_port,
                    'control_port': control_port,
                    'headless': True,
                    'executable_path': str(geckodriver),
                    'pref_dict': {
                        'network.proxy.type': 1,
                        'network.proxy.socks': '127.0.0.1',
                        'network.proxy.socks_port': socks_port,
                        'network.proxy.socks_version': 5,
                        'network.proxy.socks_remote_dns': True,
                        'network.proxy.no_proxies_on': '',
                        'network.proxy.failover_direct': False,
                    },
                    'tbb_logfile_path': str(browser_log_path),
                }
                if persistent_profile is not None:
                    driver_kwargs['tbb_profile_path'] = str(persistent_profile)
                    driver_kwargs['use_custom_profile'] = True
                if (persistent_profile is not None
                        or args.reuse_target_page_between_visits):
                    driver_kwargs['pref_dict'].update({
                        'browser.cache.disk.enable': args.enable_browser_cache_between_visits,
                        'browser.cache.memory.enable': args.enable_browser_cache_between_visits,
                        'browser.cache.offline.enable': False,
                        'network.http.use-cache': args.enable_browser_cache_between_visits,
                    })
                if driver is None:
                    driver = TorBrowserDriver(
                        str(browser_dir), tor_cfg=cm.USE_STEM,
                        **{key: value for key, value in driver_kwargs.items()
                           if key != 'tor_cfg'})
                    if args.reuse_browser_process_between_visits:
                        browser_driver = driver
                command_config = getattr(driver.command_executor, '_client_config', None)
                if command_config is None:
                    raise RuntimeError('Selenium command client does not expose its timeout config')
                command_config.timeout = args.page_load_timeout + 60
                driver.set_page_load_timeout(args.page_load_timeout)
                driver.set_script_timeout(20)
                if args.reuse_target_page_between_visits and index > 0:
                    initial_check = summary.get('initial_tor_check') or {}
                    if initial_check.get('tor_check_passed') is not True:
                        raise RuntimeError('the initial Tor check did not pass')
                    if initial_check.get('check_streams_closed_before_capture') is not True:
                        raise RuntimeError('the initial Tor check streams were not closed')
                    current_url = (driver.current_url or '').lower()
                    target_url = args.url.lower()
                    if current_url.rstrip('/') != target_url.rstrip('/'):
                        raise RuntimeError('the retained browser tab is not on the target site')
                    result.update({
                        'tor_check_passed': True,
                        'check_stream_succeeded': True,
                        'check_stream_circuit_ids': initial_check.get(
                            'check_stream_circuit_ids', []),
                        'check_stream_statuses': initial_check.get(
                            'check_stream_statuses', []),
                        'check_stream_ids': initial_check.get('check_stream_ids', []),
                        'check_streams_closed_before_capture': True,
                        'check_page_closed_before_capture': True,
                        'tor_check_reused_from_initial_visit': True,
                        'tor_check_evidence_source': 'initial_session_check',
                    })
                else:
                    check_evidence = perform_tor_check(
                        driver, controller, check_stream_ids,
                        check_stream_events, args)
                    result.update(check_evidence)
                    result['tor_check_reused_from_initial_visit'] = False
                    result['tor_check_evidence_source'] = 'initial_session_check'
                    if args.reuse_target_page_between_visits:
                        summary['initial_tor_check'] = dict(check_evidence)
                control_dir = Path(args.capture_control_dir) if args.capture_control_dir else None
                if ((index == 0 and args.warmup_site_visit)
                        or args.warmup_before_each_visit):
                    warmup = {
                        'attempted': True,
                        'visit_index': index + 1,
                        'site_url': args.url,
                        'captured_as_a_trace': False,
                        'started_utc': utc_now(),
                        'started_monotonic': time.monotonic(),
                        'settle_seconds_after_page_ready': args.warmup_settle_seconds,
                    }
                    warmup_stream_start = len(events)
                    try:
                        warmup_request, warmup_ack = request_capture_control(
                            control_dir, 'warmup', args.capture_ack_timeout, index + 1)
                        warmup['route_ready_request'] = warmup_request
                        warmup['route_ready_ack'] = warmup_ack
                        warmup['route_readiness'] = warmup_ack.get(
                            'route_readiness', {})
                        warmup_nav_start = time.monotonic()
                        driver.get(args.url)
                        warmup_page, _, warmup_content_wait = wait_for_page_content(
                            driver, args.page_content_timeout,
                            args.resource_idle_seconds,
                            require_resource_idle=False)
                        warmup['warmup_final_url'] = warmup_page.get('url')
                        warmup_url_parts = urlsplit(warmup['warmup_final_url'] or '')
                        warmup_host = warmup_url_parts.hostname or ''
                        warmup['warmup_final_url_https'] = (
                            warmup_url_parts.scheme.lower() == 'https')
                        warmup_target_domain = parsed.hostname.lower().removeprefix('www.')
                        warmup_domain_ok = (
                            warmup_host == warmup_target_domain
                            or warmup_host.endswith('.' + warmup_target_domain))
                        warmup['page_content_wait_seconds'] = warmup_content_wait
                        warmup['http_status'] = warmup_page.get('status')
                        warmup['page_content_ready'] = (
                            warmup_page.get('ready') == 'complete'
                            and bool(warmup_page.get('title'))
                            and warmup_page.get('text_length', 0) >= 40)
                        warmup['page_content_character_count'] = warmup_page.get(
                            'text_length', 0)
                        warmup['page_loaded'] = (
                            warmup['page_content_ready'] and warmup_domain_ok
                            and warmup['warmup_final_url_https']
                            and warmup_page.get('status') == 200
                            and not driver.is_connection_error_page
                            and 'Problem loading page' not in str(
                                warmup_page.get('text') or ''))
                        if not warmup['page_loaded']:
                            raise RuntimeError(
                                'uncaptured site warm-up did not reach visible HTTP 200 content')
                        if args.warmup_settle_seconds:
                            time.sleep(args.warmup_settle_seconds)
                        try:
                            clear_site_state(driver)
                            warmup['site_state_cleared'] = True
                        except Exception as exc:
                            warmup['site_state_cleared'] = False
                            raise RuntimeError('could not clear warm-up site state: ' +
                                               type(exc).__name__)
                        if args.reuse_target_page_between_visits:
                            warmup['about_blank_after_warmup'] = False
                            retained_url = driver.current_url or ''
                            retained_parts = urlsplit(retained_url)
                            warmup_parts = warmup_url_parts._replace(fragment='')
                            retained_path = retained_parts.path.rstrip('/') or '/'
                            warmup_path = warmup_parts.path.rstrip('/') or '/'
                            retained_host = (retained_parts.hostname or '').lower()
                            warmup_final_host = (warmup_parts.hostname or '').lower()
                            retained_domain_ok = (
                                retained_parts.scheme.lower() == 'https'
                                and (retained_host == warmup_target_domain
                                     or retained_host.endswith(
                                         '.' + warmup_target_domain)))
                            warmup['target_page_retained_after_warmup'] = bool(
                                retained_domain_ok
                                and retained_host == warmup_final_host
                                and retained_path == warmup_path
                                and not driver.is_connection_error_page)
                            warmup['retained_url_after_state_clear'] = retained_url
                            if not warmup['target_page_retained_after_warmup']:
                                raise RuntimeError('warm-up did not leave the browser on the target page')
                        else:
                            warmup['about_blank_after_warmup'] = close_target_site_storage(
                                driver)
                            warmup['target_page_retained_after_warmup'] = False
                            if not warmup['about_blank_after_warmup']:
                                raise RuntimeError('could not leave the warm-up page before measurement')
                        warmup_events = events[warmup_stream_start:]
                        warmup_domain = parsed.hostname.lower()
                        warmup_target_ids = {event['id'] for event in warmup_events
                            if event['status'] in ('NEW', 'SENTCONNECT')
                            and event.get('address')
                            and (event['address'].lower().rstrip('.') == warmup_domain
                                 or event['address'].lower().rstrip('.').endswith(
                                     '.' + warmup_domain))}
                        warmup['target_circuit_ids'] = sorted({
                            event['circuit_id'] for event in warmup_events
                            if event['id'] in warmup_target_ids
                            and event['status'] == 'SUCCEEDED'})
                        warmup['target_stream_ids'] = sorted(warmup_target_ids)
                        warmup['target_stream_succeeded'] = any(
                            event['id'] in warmup_target_ids
                            and event['status'] == 'SUCCEEDED'
                            for event in warmup_events)
                        terminal_statuses = {'CLOSED', 'DETACHED', 'FAILED'}
                        warmup['stream_event_count'] = len(warmup_events)
                        warmup['open_site_stream_count_after_about_blank'] = len({
                            event['id'] for event in warmup_events
                            if event['status'] in ('NEW', 'SENTCONNECT', 'SUCCEEDED')
                        } - {event['id'] for event in warmup_events
                             if event['status'] in terminal_statuses})
                        warmup['elapsed_seconds'] = round(
                            time.monotonic() - warmup['started_monotonic'], 3)
                        warmup['completed_utc'] = utc_now()
                        warmup['completed_monotonic'] = time.monotonic()
                        warmup['passed'] = (
                            warmup_ack.get('ok') is True
                            and warmup['route_readiness'].get('passed') is True
                            and warmup['page_loaded']
                            and warmup['site_state_cleared'])
                        summary['site_warmups'].append(warmup)
                        summary['site_warmup'] = warmup
                        write_json(run_dir / 'summary.json', summary)
                    except Exception:
                        warmup['passed'] = False
                        warmup['elapsed_seconds'] = round(
                            time.monotonic() - warmup['started_monotonic'], 3)
                        warmup['completed_utc'] = utc_now()
                        summary['site_warmups'].append(warmup)
                        summary['site_warmup'] = warmup
                        write_json(run_dir / 'summary.json', summary)
                        raise
                if index == 0 and not args.reuse_check_circuit_for_first_site:
                    wait = controller.get_newnym_wait()
                    if wait > 0:
                        time.sleep(wait)
                    controller.signal(Signal.NEWNYM)
                result['capture_window'] = {'mode': 'site_navigation_only' if control_dir else 'disabled'}
                capture_open = False
                target_stream_start = len(events)
                try:
                    if control_dir:
                        start_request, start_ack = request_capture_control(
                            control_dir, 'start', args.capture_ack_timeout, index + 1)
                        result['capture_window']['start_request'] = start_request
                        result['capture_window']['start_ack'] = start_ack
                        capture_open = True
                    target_stream_start = len(events)
                    navigation_action = (
                        'refresh' if args.reuse_target_page_between_visits else 'navigate')
                    result['site_navigation_action'] = navigation_action
                    nav_start = capture_marker(control_dir, 'site_navigation_started',
                        requested_url=args.url, navigation_action=navigation_action)
                    result['capture_window']['navigation_started'] = nav_start
                    if args.reuse_target_page_between_visits:
                        driver.refresh()
                    else:
                        driver.get(args.url)
                    page, content_stable, content_wait = wait_for_page_content(
                        driver, args.page_content_timeout, args.resource_idle_seconds,
                        require_resource_idle=args.fixed_window_seconds is None)
                    result.update({
                        'final_url': page.get('url'),
                        'title': page.get('title'),
                        'ready_state': page.get('ready'),
                        'document_domain': page.get('domain'),
                        'http_status': page.get('status'),
                        'page_excerpt': page.get('text'),
                        'resource_origins': page.get('resource_origins', []),
                        'page_content_character_count': page.get('text_length', 0),
                        'resource_timing_entry_count': page.get('resource_count', 0),
                        'page_content_stable': content_stable,
                        'page_content_wait_seconds': content_wait,
                        'page_content_ready': (page.get('ready') == 'complete'
                            and bool(page.get('title'))
                            and page.get('text_length', 0) >= 40),
                    })
                    final_host = urlsplit(result['final_url'] or '').hostname or ''
                    target_domain = parsed.hostname.lower().removeprefix('www.')
                    domain_ok = (final_host == target_domain
                                 or final_host.endswith('.' + target_domain))
                    content = str(page.get('text') or '')
                    error_page = driver.is_connection_error_page or 'Problem loading page' in content
                    result['page_loaded'] = (page.get('ready') == 'complete' and bool(page.get('title'))
                        and domain_ok
                        and (content_stable or args.fixed_window_seconds is not None)
                        and page.get('text_length', 0) >= 40 and not error_page)
                    if not content_stable and args.fixed_window_seconds is None:
                        result['errors'].append(
                            'target page did not show visible text and a quiet resource list '
                            'within {} seconds'.format(args.page_content_timeout))
                    if args.fixed_window_seconds is not None:
                        result['resource_timing_at_readiness'] = (
                            browser_resource_timing_snapshot(driver))
                        elapsed = time.monotonic() - nav_start['monotonic']
                        remaining = args.fixed_window_seconds - elapsed
                        if remaining > 0:
                            time.sleep(remaining)
                        window_elapsed = time.monotonic() - nav_start['monotonic']
                        result['fixed_capture_window_seconds'] = round(window_elapsed, 3)
                        result['resource_timing_at_window_end'] = (
                            browser_resource_timing_snapshot(driver))
                        if window_elapsed > args.fixed_window_seconds + 1.0:
                            result['page_loaded'] = False
                            result['errors'].append(
                                'page content was not ready within the fixed capture window')
                    nav_complete = capture_marker(control_dir, 'site_navigation_completed',
                        final_url=result.get('final_url'), http_status=result.get('http_status'),
                        page_loaded=result['page_loaded'],
                        fixed_window_seconds=args.fixed_window_seconds)
                    result['capture_window']['navigation_completed'] = nav_complete
                    time.sleep(max(0.0, args.capture_settle_seconds))
                finally:
                    if capture_open:
                        stop_request, stop_ack = request_capture_control(
                            control_dir, 'stop', args.capture_ack_timeout, index + 1)
                        result['capture_window']['stop_request'] = stop_request
                        result['capture_window']['stop_ack'] = stop_ack
                    navigation_start = result['capture_window'].get(
                        'navigation_started', {}).get('monotonic')
                    result['capture_window']['site_stream_events'] = ([
                        event for event in events[target_stream_start:]
                        if event['observed_monotonic'] >= navigation_start
                    ] if isinstance(navigation_start, (int, float)) else [])
                    result['capture_window']['site_stream_domains'] = sorted({
                        event['address'].lower().rstrip('.')
                        for event in result['capture_window']['site_stream_events']
                        if event.get('address')
                    })
                    result['capture_window']['tor_check_stream_seen'] = any(
                        domain == 'check.torproject.org'
                        for domain in result['capture_window']['site_stream_domains'])
                if (driver is not None and args.reuse_target_page_between_visits):
                    try:
                        clear_site_state(driver)
                        result['site_cookies_cleared_after_visit'] = True
                        result['site_storage_cleared_after_visit'] = True
                    except Exception as exc:
                        result['site_cookies_cleared_after_visit'] = False
                        result['site_storage_cleared_after_visit'] = False
                        result['errors'].append('site state cleanup: ' + type(exc).__name__)
                elif persistent_profile is not None and driver is not None:
                    try:
                        driver.delete_all_cookies()
                        result['site_cookies_cleared_after_visit'] = True
                    except Exception as exc:
                        result['site_cookies_cleared_after_visit'] = False
                        result['errors'].append('cookie cleanup: ' + type(exc).__name__)
                site_domain = parsed.hostname.lower().removeprefix('www.')
                sample_events = events[target_stream_start:]
                wanted_ids = {event['id'] for event in sample_events
                    if event['status'] in ('NEW', 'SENTCONNECT') and event['address']
                    and (event['address'].lower().rstrip('.') == site_domain
                         or event['address'].lower().rstrip('.').endswith('.' + site_domain))}
                success_events = [event for event in sample_events
                    if event['id'] in wanted_ids and event['status'] == 'SUCCEEDED']
                result['target_stream_succeeded'] = bool(success_events)
                if (args.reuse_target_page_between_visits
                        and not result['target_stream_succeeded']):
                    warmup_evidence = summary.get('site_warmup', {})
                    result['target_stream_succeeded'] = (
                        warmup_evidence.get('target_stream_succeeded') is True)
                    result['target_stream_evidence_source'] = (
                        'initial_uncaptured_site_warmup')
                    result['target_warmup_stream_ids'] = warmup_evidence.get(
                        'target_stream_ids', [])
                else:
                    result['target_stream_evidence_source'] = 'measured_visit_stream'
                result['target_circuit_ids'] = sorted({event['circuit_id'] for event in success_events})
                result['target_circuit_path_events'] = [
                    event for event in circuit_events
                    if event['circuit_id'] in set(result['target_circuit_ids'])]
                result['http_200_confirmed'] = result['http_status'] == 200
                result['passed'] = (result['tor_check_passed'] and result['page_loaded']
                    and result['http_200_confirmed'] and result['target_stream_succeeded'])
            except Exception as exc:
                result['errors'].append(type(exc).__name__ + ': ' + str(exc)[:400])
            finally:
                result['elapsed_seconds'] = time.monotonic() - start
                if driver is not None:
                    if (args.reuse_browser_process_between_visits
                            and args.reuse_target_page_between_visits
                            and index + 1 < args.visits):
                        result['browser_kept_open_for_next_visit'] = True
                        result['browser_kept_target_page_for_next_visit'] = True
                        result['browser_closed'] = False
                    elif args.reuse_browser_process_between_visits and index + 1 < args.visits:
                        try:
                            driver.get('about:blank')
                            result['browser_kept_open_for_next_visit'] = True
                            result['browser_closed'] = False
                        except Exception as exc:
                            result['browser_kept_open_for_next_visit'] = False
                            result['browser_closed'] = False
                            result['errors'].append('browser keepalive: ' + type(exc).__name__)
                    else:
                        try:
                            driver.quit()
                            result['browser_closed'] = True
                            if args.reuse_browser_process_between_visits:
                                browser_driver = None
                            driver = None
                        except Exception as exc:
                            result['browser_closed'] = False
                            result['errors'].append('browser close: ' + type(exc).__name__)
                summary['visits'].append(result)
                write_json(run_dir / 'summary.json', summary)
            if not result['passed']:
                break

        summary['stream_event_count'] = len(events)
        summary['target_site_streams'] = [event for event in events
            if event['address'] and (event['address'].lower().rstrip('.') == parsed.hostname
                or event['address'].lower().rstrip('.').endswith('.' + parsed.hostname))]
        summary['unique_target_circuit_count'] = len({cid for visit in summary['visits']
            for cid in visit.get('target_circuit_ids', [])})
        summary['all_visits_passed'] = (len(summary['visits']) == args.visits
            and all(visit['passed'] for visit in summary['visits']))
        circuit_sets = [set(visit.get('target_circuit_ids', []))
                        for visit in summary['visits']]
        common_circuits = (set.intersection(*circuit_sets)
                           if circuit_sets and all(circuit_sets) else set())
        summary['common_target_circuit_ids'] = sorted(common_circuits)
        summary['same_target_circuit_across_visits'] = (
            len(summary['visits']) == args.visits and bool(common_circuits))
        summary['target_circuit_path_events'] = [
            event for visit in summary['visits']
            for event in visit.get('target_circuit_path_events', [])]
        summary['cleanup_verified'] = True
    except Exception as exc:
        summary['errors'].append(type(exc).__name__ + ': ' + str(exc)[:400])
    finally:
        if 'driver' in locals() and driver is not None:
            try:
                driver.quit()
            except Exception:
                pass
        if 'controller' in locals():
            try:
                controller.remove_event_listener(collect_stream)
                controller.remove_event_listener(collect_circuit)
                controller.close()
            except Exception:
                pass
        if 'tor_process' in locals() and tor_process is not None and tor_process.poll() is None:
            tor_process.terminate()
            try:
                tor_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                tor_process.kill()
                tor_process.wait(timeout=5)
        if 'tor_process_log' in locals():
            tor_process_log.close()
        if 'tor_process' in locals() and tor_process is not None:
            summary['tor_process_exit_code'] = tor_process.returncode
            summary['cleanup_verified'] = tor_process.poll() is not None
        elif not summary.get('cleanup_verified'):
            summary['cleanup_verified'] = True
        if 'private_runtime' in locals():
            shutil.rmtree(str(private_runtime), ignore_errors=True)
        summary['passed'] = bool(summary.get('all_visits_passed')
            and summary.get('cleanup_verified') and not summary['errors'])
        write_json(run_dir / 'summary.json', summary)
        print(json.dumps(summary, indent=2, sort_keys=True), flush=True)
    return 0 if summary['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

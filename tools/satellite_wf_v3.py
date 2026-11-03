#!/usr/bin/env python3
"""Offline configuration, F/S provenance, and training-admission gates for WF V3."""
import argparse
import datetime
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit, urlunsplit


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "protocols" / "satellite_wf_v3" / "runtime_config.json"
DEFAULT_EVIDENCE = ROOT / "protocols" / "satellite_wf_v3" / "source_evidence.json"
REQUIRED_SEMANTICS = (
    "browser_tor_versions", "cache_navigation", "capture_point_filter",
    "packet_unit", "direction", "time_origin", "window",
    "session_provenance",
)
ATTESTED_SOURCE_AUDIT_STATUS = "user_attested_with_unresolved_semantics"
ATTESTED_SOURCE_OVERRIDE_MODE = "user_attested_spacesec2024_dataset_identity"
ATTESTED_SOURCE_DOI = "10.5281/zenodo.10641853"
REQUIRED_SAMPLE_GATES = (
    "target_identity_verified", "target_page_success_verified",
    "access_challenge_absent", "tor_target_stream_verified",
    "target_tor_circuit_three_hops_verified",
    "route_nat_verified", "bidirectional_satellite_route_verified",
    "capture_interface_verified", "capture_loss_zero",
    "offloads_disabled_verified", "pcap_trace_audit_passed",
    "topology_events_recorded", "actual_tor_path_recorded",
    "capture_window_order_verified", "clock_pair_verified",
    "cleanup_verified",
)


def load_json(path):
    with Path(path).open("r", encoding="utf-8") as stream:
        return json.load(stream)


def write_json(path, value):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(str(target) + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n",
                         encoding="utf-8")
    temporary.replace(target)


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_sha256(value):
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def normalize_site_url(value):
    if not isinstance(value, str):
        raise ValueError("URL must be a string")
    parsed = urlsplit(value.strip())
    if (parsed.scheme.lower() not in ("http", "https") or not parsed.hostname
            or parsed.username or parsed.password):
        raise ValueError("URL must be an absolute HTTP(S) URL without credentials")
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))


def resolve_ref(reference, base):
    path = Path(reference.get("path", ""))
    return path if path.is_absolute() else Path(base) / path


def verify_ref(reference, base, label, errors):
    if not isinstance(reference, dict):
        errors.append(label + ": evidence reference must be an object")
        return None
    path = resolve_ref(reference, base).resolve()
    expected = str(reference.get("sha256", "")).lower()
    if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        errors.append(label + ": missing or malformed SHA-256")
        return str(path)
    if not path.is_file():
        errors.append(label + ": evidence file is missing: " + str(path))
        return str(path)
    actual = sha256_file(path)
    if actual != expected:
        errors.append(label + ": evidence hash changed: " + str(path))
    return str(path)


def _load_dataset_identity_attestation(evidence, base, errors):
    override = evidence.get("training_admission_override", {})
    if not override:
        return None
    if not isinstance(override, dict):
        errors.append("training_admission_override must be an object")
        return None
    if override.get("mode") != ATTESTED_SOURCE_OVERRIDE_MODE:
        errors.append("training_admission_override has an unsupported mode")
        return None
    reference = override.get("attestation")
    path_text = verify_ref(reference, base,
                           "training_admission_override.attestation", errors)
    if not path_text or not Path(path_text).is_file():
        return None
    try:
        record = load_json(path_text)
    except (OSError, ValueError, TypeError) as exc:
        errors.append("dataset identity attestation cannot be parsed: {}".format(exc))
        return None
    if not isinstance(record, dict):
        errors.append("dataset identity attestation must be a JSON object")
        return None
    authorization = record.get("authorization", {})
    if not isinstance(authorization, dict):
        authorization = {}
    paper_source = record.get("paper_source", {})
    if not isinstance(paper_source, dict):
        paper_source = {}
    release = evidence.get("published_release_candidate", {})
    if not isinstance(release, dict):
        release = {}
    site_reference = {
        "path": release.get("candidate_site_list_path", ""),
        "sha256": release.get("candidate_site_list_sha256", ""),
    }
    site_path_text = verify_ref(site_reference, base,
                                "published_release_candidate.candidate_site_list", errors)
    expected_class_map = {}
    if site_path_text and Path(site_path_text).is_file():
        try:
            site_list = load_json(site_path_text)
            entries = site_list.get("entries", [])
            if (site_list.get("status") !=
                    "user_attested_binding_to_current_trace_labels"
                    or not isinstance(entries, list) or len(entries) != 75):
                errors.append("user-attested site list must contain the 75 indexed entries")
            else:
                for index, entry in enumerate(entries):
                    if (not isinstance(entry, dict)
                            or entry.get("paper_list_index") != index
                            or entry.get("trace_class_id") != index
                            or entry.get("trace_class_id_binding") !=
                            "user_attested_zero_based_appendix_index"):
                        errors.append("user-attested site list indices must map 0-74 in order")
                        break
                    try:
                        expected_class_map[str(index)] = normalize_site_url(
                            "http://" + entry["domain"] + "/")
                    except (KeyError, ValueError):
                        errors.append("user-attested site list contains an invalid domain")
                        break
        except (OSError, ValueError, TypeError) as exc:
            errors.append("user-attested site list cannot be parsed: {}".format(exc))
    checks = (
        (record.get("schema_version") == 1, "schema_version must be 1"),
        (record.get("attestation_type") == "user_confirmed_dataset_identity",
         "attestation_type is invalid"),
        (record.get("confirmed_by_user") is True, "user confirmation is missing"),
        (record.get("dataset_doi") == ATTESTED_SOURCE_DOI,
         "dataset DOI does not match the supported release"),
        (record.get("class_id_binding_rule") ==
         "trace_class_id_equals_zero_based_paper_appendix_index",
         "class ID binding rule is not the attested paper-index rule"),
        (record.get("local_domains") == {
            "F": "dataset/tor_fiber", "S": "dataset/tor_starlink"},
         "local dataset scope does not match the current F/S roots"),
        (record.get("class_id_range") == [0, 74],
         "class ID range must be 0-74"),
        (record.get("url_mapping_convention") == "http://<Appendix A domain>/",
         "URL mapping convention is invalid"),
        (paper_source.get("site_list_sha256") == site_reference["sha256"],
         "attestation does not pin the current user-attested site list"),
        (paper_source.get("sha256") == release.get("paper_sha256"),
         "attestation does not pin the candidate paper version"),
        (authorization.get("allow_training_admission") is True,
         "authorization does not allow training admission"),
        (authorization.get("allow_unresolved_semantics") is True,
         "authorization does not allow unresolved semantics"),
        (authorization.get("scientific_fidelity_claim") is False,
         "attestation must not claim scientific fidelity"),
    )
    valid = True
    for passed, message in checks:
        if not passed:
            errors.append("dataset identity attestation: " + message)
            valid = False
    if not valid or not expected_class_map:
        return None
    return {
        "type": record["attestation_type"],
        "path": path_text,
        "sha256": reference.get("sha256"),
        "dataset_doi": record["dataset_doi"],
        "class_id_binding_rule": record["class_id_binding_rule"],
        "confirmed_by_user": True,
        "authorization": authorization,
        "site_list_path": site_path_text,
        "site_list_sha256": site_reference["sha256"],
        "expected_class_map": expected_class_map,
    }


def _verify_source_audit_attestation(source_audit):
    attestation = source_audit.get("user_attestation")
    if not isinstance(attestation, dict):
        return False
    authorization = attestation.get("authorization", {})
    if not isinstance(authorization, dict):
        return False
    path = Path(attestation.get("path", ""))
    expected = str(attestation.get("sha256", "")).lower()
    if (attestation.get("type") != "user_confirmed_dataset_identity"
            or attestation.get("dataset_doi") != ATTESTED_SOURCE_DOI
            or attestation.get("confirmed_by_user") is not True
            or attestation.get("class_id_binding_rule") !=
            "trace_class_id_equals_zero_based_paper_appendix_index"
            or not authorization.get("allow_training_admission")
            or not authorization.get("allow_unresolved_semantics")
            or authorization.get("scientific_fidelity_claim") is not False
            or len(expected) != 64
            or any(char not in "0123456789abcdef" for char in expected)
            or not path.is_file()):
        return False
    if sha256_file(path) != expected:
        return False
    try:
        attestation_record = load_json(path)
    except (OSError, ValueError, TypeError):
        return False
    if not isinstance(attestation_record, dict):
        return False
    record_authorization = attestation_record.get("authorization", {})
    paper_source = attestation_record.get("paper_source", {})
    if (not isinstance(record_authorization, dict)
            or not isinstance(paper_source, dict)
            or attestation_record.get("schema_version") != 1
            or attestation_record.get("attestation_type") !=
            "user_confirmed_dataset_identity"
            or attestation_record.get("confirmed_by_user") is not True
            or attestation_record.get("dataset_doi") != ATTESTED_SOURCE_DOI
            or attestation_record.get("class_id_binding_rule") !=
            "trace_class_id_equals_zero_based_paper_appendix_index"
            or attestation_record.get("local_domains") != {
                "F": "dataset/tor_fiber", "S": "dataset/tor_starlink"}
            or attestation_record.get("class_id_range") != [0, 74]
            or attestation_record.get("url_mapping_convention") !=
            "http://<Appendix A domain>/"
            or record_authorization.get("allow_training_admission") is not True
            or record_authorization.get("allow_unresolved_semantics") is not True
            or record_authorization.get("scientific_fidelity_claim") is not False):
        return False
    site_list_path = Path(attestation.get("site_list_path", ""))
    site_list_sha = str(attestation.get("site_list_sha256", "")).lower()
    if (len(site_list_sha) != 64
            or any(char not in "0123456789abcdef" for char in site_list_sha)
            or not site_list_path.is_file()
            or sha256_file(site_list_path) != site_list_sha
            or paper_source.get("site_list_sha256") != site_list_sha):
        return False
    try:
        site_list = load_json(site_list_path)
        entries = site_list.get("entries", [])
    except (OSError, ValueError, TypeError, AttributeError):
        return False
    if (site_list.get("status") != "user_attested_binding_to_current_trace_labels"
            or not isinstance(entries, list) or len(entries) != 75):
        return False
    expected_map = {}
    for index, entry in enumerate(entries):
        if (not isinstance(entry, dict)
                or entry.get("paper_list_index") != index
                or entry.get("trace_class_id") != index
                or entry.get("trace_class_id_binding") !=
                "user_attested_zero_based_appendix_index"):
            return False
        try:
            expected_map[str(index)] = normalize_site_url(
                "http://" + entry["domain"] + "/")
        except (KeyError, ValueError):
            return False
    common_map = source_audit.get("common_class_map")
    return (
        common_map == expected_map
        and source_audit.get("common_class_ids") == [str(index) for index in range(75)]
        and source_audit.get("class_mapping_sha256") == canonical_sha256(expected_map)
        and source_audit.get("training_admission") ==
        "allowed_with_user_attestation_and_semantic_caveats"
        and bool(source_audit.get("unresolved_semantics")))


def _is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _parse_utc(value):
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    normalized = value[:-1] + "+0000" if value.endswith("Z") else value
    normalized = normalized[:-3] + normalized[-2:] if normalized[-3:-2] == ":" else normalized
    for pattern in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            parsed = datetime.datetime.strptime(normalized, pattern)
            if parsed.utcoffset() != datetime.timedelta(0):
                raise ValueError("timestamp must be expressed in UTC")
            return parsed.timestamp()
        except ValueError:
            continue
    raise ValueError("timestamp must be ISO-8601 UTC")


def _audit_sample_time(label, sample, errors):
    bounds = sample.get("time_boundaries", {})
    ordered_fields = (
        ("raw_capture_start", "navigation_start"),
        ("navigation_start", "navigation_complete"),
        ("navigation_complete", "raw_capture_end"),
    )
    utc_values = {}
    monotonic_values = {}
    for name in ("raw_capture_start", "navigation_start", "navigation_complete",
                 "raw_capture_end"):
        utc_field = name + "_utc"
        monotonic_field = name + "_monotonic"
        try:
            utc_values[name] = _parse_utc(bounds.get(utc_field))
        except ValueError as exc:
            errors.append(label + ": invalid time_boundaries.{} ({})".format(
                utc_field, exc))
        value = bounds.get(monotonic_field)
        if not _is_number(value):
            errors.append(label + ": time_boundaries.{} must be finite".format(
                monotonic_field))
        else:
            monotonic_values[name] = value
    for before, after in ordered_fields:
        if (before in utc_values and after in utc_values
                and utc_values[before] > utc_values[after]):
            errors.append(label + ": UTC capture/navigation boundaries are out of order")
        if (before in monotonic_values and after in monotonic_values
                and monotonic_values[before] > monotonic_values[after]):
            errors.append(label + ": monotonic capture/navigation boundaries are out of order")
    for before, after in (("raw_capture_start", "raw_capture_end"),
                          ("navigation_start", "navigation_complete")):
        if (before in monotonic_values and after in monotonic_values
                and monotonic_values[before] >= monotonic_values[after]):
            errors.append(label + ": monotonic {} must precede {}".format(before, after))
    for field in ("topology_start_seconds", "topology_end_seconds",
                  "clock_anchor_monotonic"):
        if not _is_number(bounds.get(field)):
            errors.append(label + ": time_boundaries.{} must be finite".format(field))
    try:
        _parse_utc(bounds.get("clock_anchor_utc"))
    except ValueError as exc:
        errors.append(label + ": invalid time_boundaries.clock_anchor_utc ({})".format(exc))
    if (_is_number(bounds.get("topology_start_seconds"))
            and _is_number(bounds.get("topology_end_seconds"))
            and bounds["topology_start_seconds"] > bounds["topology_end_seconds"]):
        errors.append(label + ": topology logical-time boundaries are out of order")


def validate_config(config):
    errors = []
    if config.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if config.get("protocol_id") != "starrynet-browser-tor-route-nat-v3":
        errors.append("unexpected V3 protocol_id")
    network = config.get("network", {})
    if network.get("mode") != "gre_route_nat":
        errors.append("network.mode must be gre_route_nat")
    if network.get("tunnel_interface") != network.get("capture_interface"):
        errors.append("capture must use the stable GRE interface")
    if network.get("browser_proxy_environment") != "unset":
        errors.append("direct route/NAT mode must leave browser proxy variables unset")
    if network.get("egress_interface") != "B27-default":
        errors.append("GS27 egress must be explicitly bound to B27-default")
    endpoint = network.get("fixed_object_endpoint", {})
    if not isinstance(endpoint, dict):
        errors.append("network.fixed_object_endpoint must be an object")
    else:
        try:
            address = ipaddress.IPv4Address(endpoint.get("address", ""))
            if address not in ipaddress.IPv4Network("9.27.27.0/24"):
                errors.append("fixed object endpoint must be on the GS27 B27-default subnet")
            if address == ipaddress.IPv4Address("9.27.27.10"):
                errors.append("fixed object endpoint must be separate from GS27 itself")
        except ipaddress.AddressValueError:
            errors.append("network.fixed_object_endpoint.address must be IPv4")
        if endpoint.get("network") != "GS_27" or endpoint.get("interface") != "B27-default":
            errors.append("fixed object endpoint must use the GS_27 B27-default network")
        if (not isinstance(endpoint.get("port"), int)
                or not 1 <= endpoint["port"] <= 65535):
            errors.append("network.fixed_object_endpoint.port must be between 1 and 65535")
        if endpoint.get("object_name") != "fixed-object.bin":
            errors.append("network.fixed_object_endpoint.object_name must be fixed-object.bin")
        if endpoint.get("object_size_bytes") != 1048576:
            errors.append("fixed object endpoint must serve the frozen 1 MiB object")
        if not endpoint.get("image"):
            errors.append("network.fixed_object_endpoint.image must be named")
    if network.get("client_ipv6_policy") != "disable_in_isolated_namespace":
        errors.append("V3 client must disable IPv6 in its isolated network namespace")
    pilot = config.get("pilot", {})
    for field in ("total_online_budget_seconds", "attempt_timeout_seconds",
                  "cleanup_grace_seconds", "samples_per_site", "site_count"):
        if not isinstance(pilot.get(field), int) or pilot[field] <= 0:
            errors.append("pilot.{} must be a positive integer".format(field))
    if pilot.get("max_parallel_collectors") != 1:
        errors.append("pilot concurrency must remain 1")
    link_profiles = config.get("link_profiles", {})
    expanded_profiles = []
    for name, profile in link_profiles.items():
        if name == "dynamic_runtime_integration":
            continue
        if name == "sensitivity_profiles":
            if not isinstance(profile, dict):
                errors.append("link_profiles.sensitivity_profiles must be a named object")
                continue
            expanded_profiles.extend(("sensitivity_profiles." + profile_name,
                                      profile_value)
                                     for profile_name, profile_value in profile.items())
            continue
        expanded_profiles.append((name, profile))
    for name, profile in expanded_profiles:
        if not isinstance(profile, dict):
            errors.append("link profile {} must be an object".format(name))
            continue
        if profile.get("scientific_calibration") is not False:
            errors.append("link profile {} must not claim scientific calibration".format(name))
        directions = {
            "inter_satellite": ("a_to_b", "b_to_a"),
            "satellite_ground": ("satellite_to_ground", "ground_to_satellite"),
        }
        for link_name, direction_names in directions.items():
            link = profile.get(link_name, {})
            for direction_name in direction_names:
                direction = link.get(direction_name, {})
                for field in ("rate_mbps", "extra_one_way_delay_ms", "jitter_ms",
                              "loss_percent", "queue_packets"):
                    value = direction.get(field)
                    if not _is_number(value) or value < 0:
                        errors.append("{}.{}.{}.{} must be finite and nonnegative".format(
                            name, link_name, direction_name, field))
                if (_is_number(direction.get("rate_mbps"))
                        and direction["rate_mbps"] <= 0):
                    errors.append("{}.{}.{}.rate_mbps must be positive".format(
                        name, link_name, direction_name))
                if (_is_number(direction.get("loss_percent"))
                        and direction["loss_percent"] > 100):
                    errors.append("{}.{}.{}.loss_percent cannot exceed 100".format(
                        name, link_name, direction_name))
                if (_is_number(direction.get("queue_packets"))
                        and (not isinstance(direction["queue_packets"], int)
                             or isinstance(direction["queue_packets"], bool)
                             or direction["queue_packets"] < 1)):
                    errors.append("{}.{}.{}.queue_packets must be a positive integer".format(
                        name, link_name, direction_name))
    scenarios = config.get("scenarios", [])
    if not isinstance(scenarios, list):
        errors.append("scenarios must be a list")
        scenarios = []
    scenario_ids = [item.get("id") for item in scenarios if isinstance(item, dict)]
    required_scenarios = {"no_satellite_reference", "static_satellite_path",
                          "dynamic_no_handover", "dynamic_handover"}
    if not required_scenarios.issubset(set(scenario_ids)):
        errors.append("scenarios must define no-satellite, static, dynamic-no-handover, and dynamic-handover controls")
    if len(scenario_ids) != len(set(scenario_ids)):
        errors.append("scenario IDs must be unique")
    scenario_contracts = {
        "no_satellite_reference": ("direct_reference", "direct", False, False),
        "static_satellite_path": ("static", "gre_route_nat", True, False),
        "dynamic_no_handover": ("dynamic", "gre_route_nat", True, True),
        "dynamic_handover": ("dynamic", "gre_route_nat", True, True),
    }
    profile_names = set(link_profiles) - {
        "dynamic_runtime_integration", "sensitivity_profiles"}
    sensitivity_profiles = link_profiles.get("sensitivity_profiles", {})
    if isinstance(sensitivity_profiles, dict):
        profile_names.update(sensitivity_profiles)
    for scenario in scenarios:
        if not isinstance(scenario, dict):
            errors.append("each scenario must be an object")
            continue
        if scenario.get("link_profile") not in profile_names:
            errors.append("scenario {} references an unknown link profile".format(
                scenario.get("id", "<unnamed>")))
        if scenario.get("topology_mode") not in (
                "direct_reference", "static", "dynamic"):
            errors.append("scenario {} has an unknown topology_mode".format(
                scenario.get("id", "<unnamed>")))
        if not isinstance(scenario.get("satellite_route_required"), bool):
            errors.append("scenario {} must define satellite_route_required".format(
                scenario.get("id", "<unnamed>")))
        if not isinstance(scenario.get("training_candidate"), bool):
            errors.append("scenario {} must define training_candidate".format(
                scenario.get("id", "<unnamed>")))
        if scenario.get("training_candidate") and (
                scenario.get("topology_mode") != "dynamic"
                or scenario.get("satellite_route_required") is not True
                or scenario.get("egress_mode") != "gre_route_nat"):
            errors.append("training candidates require the dynamic satellite GRE route/NAT path")
        contract = scenario_contracts.get(scenario.get("id"))
        if contract is not None:
            observed = (scenario.get("topology_mode"), scenario.get("egress_mode"),
                        scenario.get("satellite_route_required"),
                        scenario.get("training_candidate"))
            if observed != contract:
                errors.append("scenario {} violates its frozen validation role".format(
                    scenario.get("id")))
        if not scenario.get("handover_policy") or not scenario.get(
                "interruption_measurement"):
            errors.append("scenario {} must specify handover and interruption recording".format(
                scenario.get("id", "<unnamed>")))
    if config.get("training", {}).get("scientific_fidelity_claim") is not False:
        errors.append("V3 must not claim calibrated scientific fidelity")
    accepted_source_statuses = config.get("training", {}).get(
        "accepted_source_audit_statuses", ["passed"])
    if (not isinstance(accepted_source_statuses, list)
            or not accepted_source_statuses
            or any(not isinstance(status, str) for status in accepted_source_statuses)
            or any(status not in ("passed", ATTESTED_SOURCE_AUDIT_STATUS)
                   for status in accepted_source_statuses)
            or len(accepted_source_statuses) != len(set(accepted_source_statuses))):
        errors.append("training.accepted_source_audit_statuses contains an invalid status")
    if config.get("training", {}).get(
            "require_attestation_for_unresolved_semantics") is not True:
        errors.append("training must require a user attestation for unresolved semantics")
    return errors


def starrynet_link_profile(config, profile_name="engineering_baseline"):
    """Return the optional link-profile mapping consumed by StarryNet."""
    profiles = config.get("link_profiles", {})
    profile = profiles.get(profile_name)
    if profile is None:
        profile = profiles.get("sensitivity_profiles", {}).get(profile_name)
    if not isinstance(profile, dict):
        raise ValueError("unknown link profile: " + profile_name)
    return {
        "inter_satellite": profile["inter_satellite"],
        "satellite_ground": profile["satellite_ground"],
    }


def audit_source_evidence(evidence_path):
    evidence_path = Path(evidence_path).resolve()
    evidence = load_json(evidence_path)
    base = (evidence_path.parent / evidence.get("evidence_root", ".")).resolve()
    errors = []
    warnings = []
    unresolved_semantics = []
    user_attestation = _load_dataset_identity_attestation(evidence, base, errors)
    if user_attestation:
        warnings.append(
            "dataset identity and class-index binding are user-attested; "
            "they are not bytewise bound to the published Zenodo archive")
    verified_candidate_sources = []
    for index, reference in enumerate(evidence.get("candidate_sources", [])):
        label = "candidate_sources[{}]".format(index)
        path = verify_ref(reference, base, label, errors)
        verified_candidate_sources.append({
            "path": path,
            "sha256": reference.get("sha256"),
            "relation_to_current_F_S_files": reference.get(
                "relation_to_current_F_S_files", "unknown"),
        })
        relation = reference.get("relation_to_current_F_S_files")
        if relation == "user_attested":
            warnings.append(label + " is bound to F/S files by user attestation only")
        elif relation != "verified":
            warnings.append(label + " is a candidate source only; it is not bound to F/S files")

    domain_results = {}
    mappings = {}
    domain_evidence = evidence.get("domains", {})
    for domain in ("F", "S"):
        item = domain_evidence.get(domain, {})
        domain_errors = []
        mapping = item.get("class_to_url", {})
        if not isinstance(mapping, dict):
            mapping = {}
            domain_errors.append("class_to_url must be an object")
        normalized = {}
        for class_id, entry in mapping.items():
            if not isinstance(entry, dict) or not entry.get("url"):
                domain_errors.append("class {} has no URL mapping".format(class_id))
                continue
            try:
                normalized_url = normalize_site_url(entry["url"])
            except ValueError as exc:
                domain_errors.append("class {} has invalid URL mapping: {}".format(
                    class_id, exc))
                continue
            refs = entry.get("evidence", [])
            if not refs:
                domain_errors.append("class {} mapping has no source evidence".format(class_id))
            for ref_index, ref in enumerate(refs):
                verify_ref(ref, base,
                           "{}.class_to_url.{}.evidence[{}]".format(
                               domain, class_id, ref_index), domain_errors)
            normalized[str(class_id)] = normalized_url
        mappings[domain] = normalized
        if (user_attestation
                and normalized != user_attestation.get("expected_class_map")):
            domain_errors.append(
                "{}.class_to_url differs from the user-attested Appendix A index mapping".format(
                    domain))

        semantics = item.get("semantics", {})
        for field in REQUIRED_SEMANTICS:
            fact = semantics.get(field, {"status": "unknown"})
            status = fact.get("status", "unknown") if isinstance(fact, dict) else "unknown"
            if status not in ("matched", "explained", "unknown"):
                domain_errors.append("{}.{} has invalid status".format(domain, field))
                continue
            if status == "unknown":
                caveat = "{}.{} remains unknown".format(domain, field)
                if user_attestation:
                    unresolved_semantics.append(caveat)
                else:
                    domain_errors.append(caveat)
                continue
            if status == "explained" and not fact.get("rationale"):
                domain_errors.append("{}.{} needs a rationale for the difference".format(
                    domain, field))
            if not fact.get("value"):
                domain_errors.append("{}.{} needs an observed value".format(domain, field))
            refs = fact.get("evidence", [])
            if not refs:
                domain_errors.append("{}.{} has no supporting evidence".format(domain, field))
            for ref_index, ref in enumerate(refs):
                verify_ref(ref, base,
                           "{}.semantics.{}.evidence[{}]".format(
                               domain, field, ref_index), domain_errors)

        sample_root = Path(item.get("sample_root", ""))
        if not sample_root.is_absolute():
            sample_root = base / sample_root
        observed_class_counts = {}
        malformed_files = []
        if not sample_root.is_dir():
            domain_errors.append("{} sample_root is missing: {}".format(domain, sample_root))
            observed_samples = 0
        else:
            for path in sample_root.iterdir():
                if not path.is_file():
                    continue
                match = re.fullmatch(r"(\d+)-(\d+)", path.name)
                if match is None:
                    malformed_files.append(path.name)
                    continue
                class_id = str(int(match.group(1)))
                observed_class_counts[class_id] = (
                    observed_class_counts.get(class_id, 0) + 1)
            observed_samples = sum(observed_class_counts.values())
            if malformed_files:
                domain_errors.append("{} sample root contains {} nonconforming files".format(
                    domain, len(malformed_files)))
        expected_count = item.get("sample_count")
        if isinstance(expected_count, int) and observed_samples != expected_count:
            domain_errors.append("{} sample count is {}, expected {}".format(
                domain, observed_samples, expected_count))
        expected_classes = item.get("class_count")
        if isinstance(expected_classes, int) and len(observed_class_counts) != expected_classes:
            domain_errors.append("{} class count is {}, expected {}".format(
                domain, len(observed_class_counts), expected_classes))
        if user_attestation and set(normalized) != set(observed_class_counts):
            domain_errors.append(
                "{} user-attested class mapping must cover every observed class".format(domain))
        expected_per_class = item.get("samples_per_class")
        if isinstance(expected_per_class, int):
            incorrect_classes = {
                class_id: count for class_id, count in observed_class_counts.items()
                if count != expected_per_class}
            if incorrect_classes or (expected_classes and
                                     len(observed_class_counts) != expected_classes):
                domain_errors.append("{} samples per class differ from {}: {}".format(
                    domain, expected_per_class, incorrect_classes))
        for class_id in normalized:
            if class_id not in observed_class_counts:
                domain_errors.append("{} class {} mapping is absent from the sample root".format(
                    domain, class_id))
        domain_results[domain] = {
            "sample_root": str(sample_root),
            "expected_sample_count": expected_count,
            "observed_sample_count": observed_samples,
            "expected_class_count": expected_classes,
            "observed_class_count": len(observed_class_counts),
            "observed_samples_per_class": observed_class_counts,
            "class_mapping_count": len(normalized),
            "errors": domain_errors,
        }
        errors.extend("{}: {}".format(domain, message) for message in domain_errors)

    common_classes = sorted(set(mappings.get("F", {})) & set(mappings.get("S", {})),
                            key=lambda value: (not value.isdigit(),
                                               int(value) if value.isdigit() else value))
    equal_classes = [class_id for class_id in common_classes
                     if mappings["F"][class_id] == mappings["S"][class_id]]
    mismatched_classes = [class_id for class_id in common_classes
                          if mappings["F"][class_id] != mappings["S"][class_id]]
    if len(equal_classes) < 5:
        errors.append("fewer than five common F/S classes have the same evidenced URL")
    if mismatched_classes:
        errors.append("F/S URL mapping differs for class IDs: " + ", ".join(mismatched_classes))

    if evidence.get("domains"):
        for field in REQUIRED_SEMANTICS:
            facts = [domain_evidence.get(domain, {}).get("semantics", {}).get(field, {})
                     for domain in ("F", "S")]
            values = [fact.get("value") if isinstance(fact, dict) else None for fact in facts]
            if all(value is not None for value in values) and values[0] != values[1]:
                if not all(fact.get("status") == "explained" and fact.get("rationale")
                           for fact in facts if isinstance(fact, dict)):
                    errors.append("F/S {} differs without an explained, evidenced difference".format(
                        field))

    return {
        "schema_version": 1,
        "audit_time_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_evidence_path": str(evidence_path),
        "source_evidence_sha256": sha256_file(evidence_path),
        "status": (ATTESTED_SOURCE_AUDIT_STATUS
                   if not errors and user_attestation and unresolved_semantics
                   else "passed" if not errors else "blocked"),
        "common_class_count": len(equal_classes),
        "common_class_ids": equal_classes,
        "common_class_map": {class_id: mappings["F"][class_id]
                             for class_id in equal_classes},
        "class_mapping_sha256": canonical_sha256(
            {class_id: mappings["F"][class_id] for class_id in equal_classes}),
        "mismatched_class_ids": mismatched_classes,
        "domains": domain_results,
        "candidate_sources": verified_candidate_sources,
        "user_attestation": ({key: value for key, value in user_attestation.items()
                               if key != "expected_class_map"}
                              if user_attestation else None),
        "unresolved_semantics": unresolved_semantics,
        "warnings": warnings,
        "errors": errors,
        "training_admission": (
            "allowed_with_user_attestation_and_semantic_caveats"
            if not errors and user_attestation and unresolved_semantics
            else "allowed_after_strict_source_audit" if not errors
            else "blocked"),
        "scientific_fidelity_verified": False,
    }


def audit_candidate_manifest(source_audit_path, manifest_path):
    source_audit_path = Path(source_audit_path).resolve()
    manifest_path = Path(manifest_path).resolve()
    source_audit = load_json(source_audit_path)
    manifest = load_json(manifest_path)
    errors = []
    expected_audit_hash = manifest.get("source_audit_sha256")
    actual_audit_hash = sha256_file(source_audit_path)
    if expected_audit_hash != actual_audit_hash:
        errors.append("candidate manifest does not pin the current source-audit hash")
    root = Path(manifest.get("artifact_root", manifest_path.parent))
    if not root.is_absolute():
        root = manifest_path.parent / root
    root = root.resolve()
    seen_ids = set()
    split_by_group = {}
    mapped_classes = set(source_audit.get("common_class_ids", []))
    mapped_urls = source_audit.get("common_class_map", {})
    mapping_sha256 = source_audit.get("class_mapping_sha256")
    allowed_sources = {"F", "S", "E"}
    config_reference = manifest.get("protocol_config", {})
    if not isinstance(config_reference, dict):
        config_reference = {}
        errors.append("protocol_config must be an object with path and SHA-256")
    config_path = Path(config_reference.get("path", ""))
    if not config_path.is_absolute():
        config_path = root / config_path
    config_path = config_path.resolve()
    config_hash = str(config_reference.get("sha256", "")).lower()
    if root not in config_path.parents:
        errors.append("protocol_config path escapes artifact_root")
    if len(config_hash) != 64 or any(c not in "0123456789abcdef" for c in config_hash):
        errors.append("protocol_config SHA-256 is missing or malformed")
    elif not config_path.is_file():
        errors.append("protocol_config artifact is missing: " + str(config_path))
    elif sha256_file(config_path) != config_hash:
        errors.append("protocol_config artifact hash mismatch")
    protocol_config = {}
    if config_path.is_file():
        try:
            protocol_config = load_json(config_path)
            config_errors = validate_config(protocol_config)
            if config_errors:
                errors.extend("protocol_config: " + item for item in config_errors)
            if manifest.get("protocol_id") != protocol_config.get("protocol_id"):
                errors.append("manifest protocol_id does not match protocol_config")
        except (OSError, ValueError, TypeError) as exc:
            errors.append("protocol_config cannot be parsed: " + str(exc))
    source_status = source_audit.get("status")
    accepted_source_statuses = protocol_config.get("training", {}).get(
        "accepted_source_audit_statuses", ["passed"])
    if source_status not in accepted_source_statuses:
        errors.append("F/S source audit status is not accepted: {}".format(
            source_status))
    elif (source_status == ATTESTED_SOURCE_AUDIT_STATUS
          and not _verify_source_audit_attestation(source_audit)):
        errors.append("F/S source audit user attestation is missing, changed, or invalid")
    scenarios = {str(item.get("id")): item for item in protocol_config.get(
        "scenarios", []) if isinstance(item, dict) and item.get("id")}
    samples = manifest.get("samples", [])
    if not samples:
        errors.append("candidate manifest contains no samples")
    for index, sample in enumerate(samples):
        label = "samples[{}]".format(index)
        sample_id = str(sample.get("sample_id", ""))
        if not sample_id or sample_id in seen_ids:
            errors.append(label + ": sample_id is missing or duplicated")
        seen_ids.add(sample_id)
        if str(sample.get("class_id")) not in mapped_classes:
            errors.append(label + ": class_id is outside the audited common classes")
        expected_url = mapped_urls.get(str(sample.get("class_id")))
        try:
            observed_url = normalize_site_url(sample.get("site_url", ""))
        except ValueError:
            observed_url = ""
        if not observed_url or observed_url != expected_url:
            errors.append(label + ": site_url does not match the audited class mapping")
        page = sample.get("page_identity", {})
        try:
            requested_url = normalize_site_url(page.get("requested_url", ""))
        except ValueError:
            requested_url = ""
        if requested_url != observed_url:
            errors.append(label + ": page_identity.requested_url does not match site_url")
        final_url = str(page.get("final_url", ""))
        final_parts = urlsplit(final_url)
        if (final_parts.scheme.lower() not in ("http", "https")
                or not final_parts.hostname or final_parts.username
                or final_parts.password):
            errors.append(label + ": page_identity.final_url must be an absolute HTTP(S) URL")
        status_code = page.get("http_status")
        if not isinstance(status_code, int) or not 200 <= status_code < 300:
            errors.append(label + ": page_identity.http_status must be 2xx")
        try:
            canonical_final_url = normalize_site_url(page.get("canonical_url", ""))
            normalized_final_url = normalize_site_url(final_url)
        except ValueError:
            canonical_final_url = normalized_final_url = ""
        if not normalized_final_url or canonical_final_url != normalized_final_url:
            errors.append(label + ": page identity must pin its final canonical URL")
        if page.get("access_challenge_detected") is not False:
            errors.append(label + ": page identity has an unresolved access challenge")
        tor_path = sample.get("tor_path", {})
        for field in ("target_stream_id", "circuit_id", "stream_circuit_id",
                      "entry_fingerprint", "middle_fingerprint",
                      "exit_fingerprint"):
            if not tor_path.get(field):
                errors.append(label + ": tor_path.{} is required".format(field))
        if tor_path.get("stream_status") != "SUCCEEDED":
            errors.append(label + ": target Tor stream did not succeed")
        if tor_path.get("circuit_status") != "BUILT":
            errors.append(label + ": target Tor circuit was not BUILT")
        if (tor_path.get("circuit_id")
                and tor_path.get("stream_circuit_id")
                and tor_path.get("circuit_id") != tor_path.get("stream_circuit_id")):
            errors.append(label + ": target stream is not attached to the recorded circuit")
        fingerprints = [str(tor_path.get(field, "")).upper()
                        for field in ("entry_fingerprint", "middle_fingerprint",
                                      "exit_fingerprint")]
        if len(set(fingerprints)) != 3 or "" in fingerprints:
            errors.append(label + ": target Tor circuit must record three distinct hops")
        for fingerprint in fingerprints:
            if not re.fullmatch(r"[0-9A-F]{40}", fingerprint):
                errors.append(label + ": target Tor hop fingerprint must be 40 hex characters")
        network_path = sample.get("network_path", {})
        if network_path.get("capture_interface") != protocol_config.get(
                "network", {}).get("capture_interface"):
            errors.append(label + ": network_path.capture_interface differs from protocol_config")
        if network_path.get("egress_interface") != protocol_config.get(
                "network", {}).get("egress_interface"):
            errors.append(label + ": network_path.egress_interface differs from protocol_config")
        if not isinstance(network_path.get("route_snapshot_count"), int) or \
                network_path.get("route_snapshot_count", 0) < 1:
            errors.append(label + ": at least one actual route snapshot is required")
        satellite_ids = network_path.get("satellite_node_ids")
        satellite_limit = protocol_config.get("topology", {}).get("satellites", 0)
        if (not isinstance(satellite_ids, list) or not satellite_ids
                or any(not isinstance(node_id, int) or isinstance(node_id, bool)
                       or not 1 <= node_id <= satellite_limit
                       for node_id in satellite_ids)):
            errors.append(label + ": network_path.satellite_node_ids must record observed satellites")
        _audit_sample_time(label, sample, errors)
        browser_tor = sample.get("browser_tor", {})
        for field in ("browser_version", "tor_version"):
            if not browser_tor.get(field):
                errors.append(label + ": browser_tor.{} is required".format(field))
        for field in ("browser_tree_sha256", "tor_binary_sha256"):
            digest = str(browser_tor.get(field, "")).lower()
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                errors.append(label + ": browser_tor.{} must be a SHA-256".format(field))
        if sample.get("source_domain") not in allowed_sources:
            errors.append(label + ": source_domain must be F, S, or E")
        if not sample.get("session_id"):
            errors.append(label + ": session_id is required")
        if sample.get("protocol_config_sha256") != config_hash:
            errors.append(label + ": protocol_config_sha256 does not match the frozen config")
        if sample.get("class_mapping_sha256") != mapping_sha256:
            errors.append(label + ": class_mapping_sha256 does not match the audited mapping")
        scenario = scenarios.get(sample.get("network_scenario_id"))
        if scenario is None:
            errors.append(label + ": network_scenario_id is not defined in protocol_config")
        elif scenario.get("training_candidate") is not True:
            errors.append(label + ": network_scenario_id is diagnostic-only, not a training candidate")
        handover = sample.get("handover", {})
        handover_observed = handover.get("occurred")
        policy = scenario.get("handover_policy") if scenario else None
        if (policy == "must_not_occur_during_capture_window"
                and handover_observed is not False):
            errors.append(label + ": dynamic_no_handover sample contains a handover")
        if policy == "must_occur_and_recover":
            if handover_observed is not True or handover.get("route_recovered") is not True:
                errors.append(label + ": dynamic_handover sample lacks observed recovery")
            outage_start = handover.get("outage_start_monotonic")
            recovered = handover.get("route_recovered_monotonic")
            duration_ms = handover.get("interruption_ms")
            if not all(_is_number(value) for value in
                       (outage_start, recovered, duration_ms)):
                errors.append(label + ": handover interruption timing is incomplete")
            elif (recovered < outage_start or duration_ms < 0
                  or abs((recovered - outage_start) * 1000 - duration_ms) >
                  max(5.0, duration_ms * 0.01)):
                errors.append(label + ": handover interruption duration is inconsistent")
            else:
                capture_start = sample.get("time_boundaries", {}).get(
                    "raw_capture_start_monotonic")
                capture_end = sample.get("time_boundaries", {}).get(
                    "raw_capture_end_monotonic")
                if (_is_number(capture_start) and _is_number(capture_end)
                        and not capture_start <= outage_start <= recovered <= capture_end):
                    errors.append(label + ": handover interruption is outside the capture window")
        if sample.get("split") not in ("train", "validation", "test"):
            errors.append(label + ": split must be train, validation, or test")
        group = sample.get("split_group_id")
        if not group:
            errors.append(label + ": split_group_id is required for session leakage control")
        else:
            prior = split_by_group.setdefault(str(group), sample.get("split"))
            if prior != sample.get("split"):
                errors.append(label + ": one session group crosses dataset splits")
        gates = sample.get("gates", {})
        for gate in REQUIRED_SAMPLE_GATES:
            if gates.get(gate) is not True:
                errors.append(label + ": required gate failed or is missing: " + gate)
        artifacts = sample.get("artifacts", [])
        artifact_kinds = [item.get("kind") for item in artifacts
                          if isinstance(item, dict)]
        artifact_by_kind = {item.get("kind"): item for item in artifacts
                            if isinstance(item, dict)}
        for required_kind in ("trace", "pcap", "sample_manifest", "packet_audit",
                              "topology_events", "route_events"):
            if required_kind not in artifact_kinds:
                errors.append(label + ": missing hashed {} artifact".format(required_kind))
            elif artifact_kinds.count(required_kind) > 1:
                errors.append(label + ": duplicate {} artifacts".format(required_kind))
        artifact_hashes = {}
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                errors.append(label + ": artifact entries must be objects")
                continue
            artifact_path = Path(artifact.get("path", ""))
            if not artifact_path.is_absolute():
                artifact_path = root / artifact_path
            artifact_path = artifact_path.resolve()
            if root not in artifact_path.parents:
                errors.append(label + ": artifact path escapes artifact_root")
                continue
            if not artifact_path.is_file():
                errors.append(label + ": artifact missing: " + str(artifact_path))
                continue
            actual_artifact_hash = sha256_file(artifact_path)
            if actual_artifact_hash != artifact.get("sha256"):
                errors.append(label + ": artifact hash mismatch: " + str(artifact_path))
            else:
                artifact_hashes[artifact.get("kind")] = actual_artifact_hash
        sample_manifest_artifact = artifact_by_kind.get("sample_manifest", {})
        sample_manifest_path = Path(sample_manifest_artifact.get("path", ""))
        if not sample_manifest_path.is_absolute():
            sample_manifest_path = root / sample_manifest_path
        if sample_manifest_path.is_file():
            try:
                stored_sample = load_json(sample_manifest_path)
                for field in (
                        "sample_id", "class_id", "site_url", "source_domain",
                        "session_id", "split_group_id", "split",
                        "protocol_config_sha256", "class_mapping_sha256",
                        "network_scenario_id", "page_identity", "tor_path",
                        "network_path", "time_boundaries", "browser_tor",
                        "handover", "gates"):
                    if stored_sample.get(field) != sample.get(field):
                        errors.append(label + ": sample_manifest field {} differs from dataset manifest".format(
                            field))
            except (OSError, ValueError, TypeError) as exc:
                errors.append(label + ": sample_manifest is not valid JSON: {}".format(exc))
        packet_audit_artifact = artifact_by_kind.get("packet_audit", {})
        packet_audit_path = Path(packet_audit_artifact.get("path", ""))
        if not packet_audit_path.is_absolute():
            packet_audit_path = root / packet_audit_path
        if packet_audit_path.is_file():
            try:
                packet_audit = load_json(packet_audit_path)
                if packet_audit.get("passed") is not True:
                    errors.append(label + ": packet audit did not pass")
                if packet_audit.get("pcap_sha256") != artifact_hashes.get("pcap"):
                    errors.append(label + ": packet audit does not bind the PCAP hash")
                if packet_audit.get("trace_sha256") != artifact_hashes.get("trace"):
                    errors.append(label + ": packet audit does not bind the trace hash")
                for count_field in ("capture_packet_count", "trace_row_count"):
                    if (not isinstance(packet_audit.get(count_field), int)
                            or packet_audit[count_field] <= 0):
                        errors.append(label + ": packet audit {} must be positive".format(
                            count_field))
                auditor_hash = str(packet_audit.get("auditor_sha256", "")).lower()
                if len(auditor_hash) != 64 or any(
                        char not in "0123456789abcdef" for char in auditor_hash):
                    errors.append(label + ": packet audit must pin auditor_sha256")
            except (OSError, ValueError, TypeError) as exc:
                errors.append(label + ": packet_audit is not valid JSON: {}".format(exc))
    splits = {sample.get("split") for sample in samples}
    if not {"train", "validation", "test"}.issubset(splits):
        errors.append("candidate manifest must contain train, validation, and test assignments")
    return {
        "schema_version": 1,
        "audit_time_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "manifest_path": str(manifest_path),
        "source_audit_sha256": actual_audit_hash,
        "source_audit_status": source_status,
        "source_semantic_caveats": source_audit.get("unresolved_semantics", []),
        "status": "admitted" if not errors else "blocked",
        "sample_count": len(samples),
        "split_group_count": len(split_by_group),
        "errors": errors,
        "scientific_fidelity_verified": False,
        "claim_boundary": "This gate checks source provenance and artifact eligibility; it does not establish similarity to real Starlink traffic.",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command")
    config_parser = sub.add_parser("config-check", help="validate the static V3 configuration")
    config_parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    config_parser.add_argument("--output")
    source_parser = sub.add_parser("source-audit", help="check hashed F/S provenance evidence")
    source_parser.add_argument("--evidence", default=str(DEFAULT_EVIDENCE))
    source_parser.add_argument("--output")
    admission_parser = sub.add_parser("admission-check", help="gate a candidate dataset manifest")
    admission_parser.add_argument("--source-audit", required=True)
    admission_parser.add_argument("--manifest", required=True)
    admission_parser.add_argument("--output")
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    try:
        if args.command == "config-check":
            config = load_json(args.config)
            errors = validate_config(config)
            result = {"status": "valid" if not errors else "invalid",
                      "config_path": str(Path(args.config).resolve()),
                      "errors": errors,
                      "runtime_status": config.get("runtime_status"),
                      "scientific_fidelity_verified": False}
        elif args.command == "source-audit":
            result = audit_source_evidence(args.evidence)
        else:
            result = audit_candidate_manifest(args.source_audit, args.manifest)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        result = {"status": "error", "errors": [str(exc)],
                  "scientific_fidelity_verified": False}
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.output:
        write_json(args.output, result)
    return 0 if result.get("status") in (
        "valid", "passed", ATTESTED_SOURCE_AUDIT_STATUS, "admitted") else 2


if __name__ == "__main__":
    sys.exit(main())

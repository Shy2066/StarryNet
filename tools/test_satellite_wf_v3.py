"""Offline contract tests for the V3 provenance and route/NAT plan tools."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import satellite_wf_v3 as v3
import satellite_wf_v3_fixed_object as fixed_object
import satellite_wf_v3_route_nat as route_nat
from starrynet import sn_orchestrater
from starrynet import sn_utils
from starrynet.sn_link_profile import (direction_for_nodes, netem_arguments,
                                       validate_profile)


ROOT = Path(__file__).resolve().parents[1]


class V3ConfigTests(unittest.TestCase):
    def setUp(self):
        self.config = v3.load_json(v3.DEFAULT_CONFIG)

    def test_checked_in_config_is_structurally_valid(self):
        self.assertEqual([], v3.validate_config(self.config))
        self.assertEqual("network_profile_api_implemented_collector_not_connected",
                         self.config["runtime_status"])
        self.assertFalse(self.config["training"]["scientific_fidelity_claim"])

    def test_site_url_normalization_preserves_case_sensitive_paths(self):
        self.assertEqual("https://example.test/News/Today",
                         v3.normalize_site_url(
                             "HTTPS://EXAMPLE.TEST/News/Today/"))

    def test_route_nat_cannot_inherit_browser_proxy(self):
        config = copy.deepcopy(self.config)
        config["network"]["browser_proxy_environment"] = "https_proxy"
        self.assertIn("direct route/NAT mode must leave browser proxy variables unset",
                      v3.validate_config(config))

    def test_link_profile_rejects_invalid_loss_and_queue(self):
        config = copy.deepcopy(self.config)
        config["link_profiles"]["engineering_baseline"]["inter_satellite"][
            "a_to_b"]["loss_percent"] = 101
        errors = v3.validate_config(config)
        self.assertTrue(any(".loss_percent cannot exceed 100" in error for error in errors))

    def test_config_converts_to_the_starrynet_directional_interface(self):
        profile = v3.starrynet_link_profile(self.config)
        self.assertEqual(5000, profile["inter_satellite"]["a_to_b"]["rate_mbps"])
        validate_profile(profile)

    def test_named_sensitivity_profile_is_directional_and_uncalibrated(self):
        config = copy.deepcopy(self.config)
        sensitivity = copy.deepcopy(config["link_profiles"]["engineering_baseline"])
        sensitivity["inter_satellite"]["a_to_b"]["extra_one_way_delay_ms"] = 4
        config["link_profiles"]["sensitivity_profiles"]["stress_case"] = sensitivity
        self.assertEqual([], v3.validate_config(config))
        profile = v3.starrynet_link_profile(config, "stress_case")
        self.assertEqual(4, profile["inter_satellite"]["a_to_b"][
            "extra_one_way_delay_ms"])


class SourceAuditTests(unittest.TestCase):
    def test_current_source_evidence_is_admitted_with_user_attested_caveats(self):
        result = v3.audit_source_evidence(v3.DEFAULT_EVIDENCE)
        self.assertEqual("user_attested_with_unresolved_semantics", result["status"])
        self.assertEqual(75, result["common_class_count"])
        self.assertEqual("allowed_with_user_attestation_and_semantic_caveats",
                         result["training_admission"])
        self.assertEqual(16, len(result["unresolved_semantics"]))
        self.assertTrue(result["user_attestation"]["confirmed_by_user"])
        self.assertFalse(result["scientific_fidelity_verified"])
        self.assertEqual(6000, result["domains"]["F"]["observed_sample_count"])
        self.assertEqual(6000, result["domains"]["S"]["observed_sample_count"])

    def test_bad_user_attestation_hash_does_not_unlock_source_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attestation = root / "attestation.json"
            attestation.write_text(json.dumps({}), encoding="utf-8")
            evidence = {
                "schema_version": 1,
                "evidence_root": ".",
                "training_admission_override": {
                    "mode": v3.ATTESTED_SOURCE_OVERRIDE_MODE,
                    "attestation": {"path": "attestation.json", "sha256": "0" * 64}},
                "candidate_sources": [],
                "domains": {"F": {}, "S": {}}}
            evidence_path = root / "source_evidence.json"
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            result = v3.audit_source_evidence(evidence_path)
            self.assertEqual("blocked", result["status"])
            self.assertTrue(any("evidence hash changed" in error
                                for error in result["errors"]))

    def test_user_attested_mapping_must_match_the_pinned_appendix_order(self):
        evidence = v3.load_json(v3.DEFAULT_EVIDENCE)
        evidence["evidence_root"] = str(ROOT)
        evidence["domains"]["F"]["class_to_url"]["0"]["url"] = (
            "http://different-site.invalid/")
        with tempfile.TemporaryDirectory() as tmp:
            evidence_path = Path(tmp) / "source_evidence.json"
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            result = v3.audit_source_evidence(evidence_path)
        self.assertEqual("blocked", result["status"])
        self.assertTrue(any("differs from the user-attested Appendix A index mapping"
                            in error for error in result["errors"]))
        self.assertEqual(["0"], result["mismatched_class_ids"])

    def test_evidence_hash_mismatch_blocks_source_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = root / "source.txt"
            reference.write_text("current", encoding="utf-8")
            evidence = {
                "schema_version": 1,
                "evidence_root": ".",
                "candidate_sources": [{
                    "path": "source.txt", "sha256": "0" * 64,
                    "relation_to_current_F_S_files": "unverified"}],
                "domains": {"F": {}, "S": {}}}
            path = root / "evidence.json"
            path.write_text(json.dumps(evidence), encoding="utf-8")
            result = v3.audit_source_evidence(path)
            self.assertEqual("blocked", result["status"])
            self.assertTrue(any("hash changed" in error for error in result["errors"]))

    def test_five_class_source_audit_passes_only_with_hashed_semantics(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence_source = root / "provenance.txt"
            evidence_source.write_text("verified collection protocol", encoding="utf-8")
            evidence_ref = {"path": "provenance.txt",
                            "sha256": v3.sha256_file(evidence_source)}
            domains = {}
            for domain in ("F", "S"):
                sample_root = root / domain
                sample_root.mkdir()
                for class_id in range(5):
                    for index in range(2):
                        (sample_root / "{}-{}".format(class_id, index)).write_text(
                            "trace", encoding="utf-8")
                semantics = {}
                for field in v3.REQUIRED_SEMANTICS:
                    semantics[field] = {"status": "matched", "value": "same",
                                        "evidence": [evidence_ref]}
                domains[domain] = {
                    "sample_root": domain, "sample_count": 10,
                    "class_count": 5, "samples_per_class": 2,
                    "class_to_url": {
                        str(class_id): {
                            "url": "https://SITE{}.test/".format(class_id),
                            "evidence": [evidence_ref]}
                        for class_id in range(5)},
                    "semantics": semantics}
            evidence_path = root / "source_evidence.json"
            evidence_path.write_text(json.dumps({
                "schema_version": 1, "evidence_root": ".",
                "domains": domains, "candidate_sources": []}),
                encoding="utf-8")
            result = v3.audit_source_evidence(evidence_path)
            self.assertEqual("passed", result["status"], result["errors"])
            self.assertEqual(5, result["common_class_count"])


class AdmissionTests(unittest.TestCase):
    def test_valid_candidate_pins_config_mapping_artifacts_and_session_splits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact_root = root / "dataset"
            artifact_root.mkdir()
            config_path = artifact_root / "protocol" / "runtime_config.json"
            config_path.parent.mkdir()
            config_path.write_text(v3.DEFAULT_CONFIG.read_text(encoding="utf-8"),
                                   encoding="utf-8")
            config_hash = v3.sha256_file(config_path)
            class_map = {"0": "https://example.test"}
            mapping_hash = v3.canonical_sha256(class_map)
            source_audit_path = root / "source_audit.json"
            source_audit_path.write_text(json.dumps({
                "status": "passed",
                "common_class_ids": ["0"],
                "common_class_map": class_map,
                "class_mapping_sha256": mapping_hash,
            }), encoding="utf-8")
            manifest = {
                "protocol_id": "starrynet-browser-tor-route-nat-v3",
                "source_audit_sha256": v3.sha256_file(source_audit_path),
                "artifact_root": ".",
                "protocol_config": {"path": "protocol/runtime_config.json",
                                    "sha256": config_hash},
                "samples": []}
            for index, split in enumerate(("train", "validation", "test")):
                sample_dir = artifact_root / "samples" / str(index)
                sample_dir.mkdir(parents=True)
                artifacts = []
                for kind, name in (("trace", "trace.tsv"),
                                   ("pcap", "capture.pcap"),
                                   ("sample_manifest", "sample.json"),
                                   ("topology_events", "topology_events.jsonl"),
                                   ("route_events", "route_events.jsonl")):
                    path = sample_dir / name
                    path.write_text("artifact {} {}".format(index, kind),
                                    encoding="utf-8")
                    artifacts.append({
                        "kind": kind,
                        "path": str(path.relative_to(artifact_root)),
                        "sha256": v3.sha256_file(path)})
                manifest["samples"].append({
                    "sample_id": "sample-{}".format(index),
                    "class_id": "0",
                    "site_url": "https://example.test",
                    "source_domain": "E",
                    "session_id": "session-{}".format(index),
                    "split_group_id": "session-{}".format(index),
                    "split": split,
                    "protocol_config_sha256": config_hash,
                    "class_mapping_sha256": mapping_hash,
                    "network_scenario_id": "dynamic_no_handover",
                    "page_identity": {
                        "requested_url": "https://example.test",
                        "final_url": "https://example.test/",
                        "canonical_url": "https://example.test/",
                        "http_status": 200,
                        "access_challenge_detected": False},
                    "tor_path": {
                        "target_stream_id": "7", "stream_status": "SUCCEEDED",
                        "circuit_id": "3", "stream_circuit_id": "3",
                        "circuit_status": "BUILT", "entry_fingerprint": "A" * 40,
                        "middle_fingerprint": "B" * 40, "exit_fingerprint": "C" * 40},
                    "network_path": {"capture_interface": "wf-gre0",
                                     "egress_interface": "B27-default",
                                     "route_snapshot_count": 2,
                                     "satellite_node_ids": [3, 12]},
                    "time_boundaries": {
                        "raw_capture_start_utc": "2026-01-01T00:00:00Z",
                        "raw_capture_start_monotonic": 100,
                        "navigation_start_utc": "2026-01-01T00:00:05Z",
                        "navigation_start_monotonic": 105,
                        "navigation_complete_utc": "2026-01-01T00:00:15Z",
                        "navigation_complete_monotonic": 115,
                        "raw_capture_end_utc": "2026-01-01T00:00:20Z",
                        "raw_capture_end_monotonic": 120,
                        "clock_anchor_utc": "2026-01-01T00:00:10Z",
                        "clock_anchor_monotonic": 110,
                        "topology_start_seconds": 10,
                        "topology_end_seconds": 20},
                    "browser_tor": {
                        "browser_version": "Tor Browser test",
                        "tor_version": "Tor test",
                        "browser_tree_sha256": "a" * 64,
                        "tor_binary_sha256": "b" * 64},
                    "handover": {"occurred": False,
                                 "route_recovered": False,
                                 "outage_start_monotonic": None,
                                 "route_recovered_monotonic": None,
                                 "interruption_ms": None},
                    "gates": dict((name, True)
                                  for name in v3.REQUIRED_SAMPLE_GATES),
                    "artifacts": artifacts})
                sample = manifest["samples"][-1]
                artifacts_by_kind = {artifact["kind"]: artifact
                                     for artifact in sample["artifacts"]}
                packet_audit_path = sample_dir / "packet_audit.json"
                packet_audit_path.write_text(json.dumps({
                    "passed": True,
                    "pcap_sha256": artifacts_by_kind["pcap"]["sha256"],
                    "trace_sha256": artifacts_by_kind["trace"]["sha256"],
                    "capture_packet_count": 1,
                    "trace_row_count": 1,
                    "auditor_sha256": v3.sha256_file(__file__),
                }), encoding="utf-8")
                sample["artifacts"].append({
                    "kind": "packet_audit",
                    "path": str(packet_audit_path.relative_to(artifact_root)),
                    "sha256": v3.sha256_file(packet_audit_path)})
                sample_metadata = {field: sample[field] for field in (
                    "sample_id", "class_id", "site_url", "source_domain",
                    "session_id", "split_group_id", "split",
                    "protocol_config_sha256", "class_mapping_sha256",
                    "network_scenario_id", "page_identity", "tor_path",
                    "network_path", "time_boundaries", "browser_tor",
                    "handover", "gates")}
                sample_manifest_artifact = artifacts_by_kind["sample_manifest"]
                sample_manifest_path = sample_dir / "sample.json"
                sample_manifest_path.write_text(json.dumps(sample_metadata),
                                                encoding="utf-8")
                sample_manifest_artifact["sha256"] = v3.sha256_file(
                    sample_manifest_path)
            manifest_path = artifact_root / "dataset_manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            result = v3.audit_candidate_manifest(source_audit_path, manifest_path)
            self.assertEqual("admitted", result["status"], result["errors"])
            self.assertFalse(result["scientific_fidelity_verified"])
            for sample in manifest["samples"]:
                sample["network_scenario_id"] = "static_satellite_path"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            diagnostic_result = v3.audit_candidate_manifest(
                source_audit_path, manifest_path)
            self.assertEqual("blocked", diagnostic_result["status"])
            self.assertTrue(any("diagnostic-only" in error
                                for error in diagnostic_result["errors"]))
            for sample in manifest["samples"]:
                sample["network_scenario_id"] = "dynamic_handover"
                sample["handover"] = {
                    "occurred": True, "route_recovered": True,
                    "outage_start_monotonic": 110,
                    "route_recovered_monotonic": 112.5,
                    "interruption_ms": 2500}
                sample_manifest_artifact = next(
                    artifact for artifact in sample["artifacts"]
                    if artifact["kind"] == "sample_manifest")
                sample_manifest_path = artifact_root / sample_manifest_artifact["path"]
                sample_metadata = {field: sample[field] for field in (
                    "sample_id", "class_id", "site_url", "source_domain",
                    "session_id", "split_group_id", "split",
                    "protocol_config_sha256", "class_mapping_sha256",
                    "network_scenario_id", "page_identity", "tor_path",
                    "network_path", "time_boundaries", "browser_tor",
                    "handover", "gates")}
                sample_manifest_path.write_text(json.dumps(sample_metadata),
                                                encoding="utf-8")
                sample_manifest_artifact["sha256"] = v3.sha256_file(
                    sample_manifest_path)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            handover_result = v3.audit_candidate_manifest(
                source_audit_path, manifest_path)
            self.assertEqual("admitted", handover_result["status"],
                             handover_result["errors"])

    def test_unpassed_source_audit_blocks_training_admission(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_audit = root / "source_audit.json"
            source_audit.write_text(json.dumps({"status": "blocked"}),
                                    encoding="utf-8")
            manifest = root / "dataset_manifest.json"
            manifest.write_text(json.dumps({
                "source_audit_sha256": v3.sha256_file(source_audit),
                "artifact_root": ".", "protocol_config": {}, "samples": []}),
                encoding="utf-8")
            result = v3.audit_candidate_manifest(source_audit, manifest)
            self.assertEqual("blocked", result["status"])
            self.assertIn("F/S source audit status is not accepted: blocked",
                          result["errors"])

    def test_user_attested_source_status_requires_live_attestation_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact_root = root / "dataset"
            artifact_root.mkdir()
            config_path = artifact_root / "runtime_config.json"
            config_path.write_text(v3.DEFAULT_CONFIG.read_text(encoding="utf-8"),
                                   encoding="utf-8")
            site_list_path = root / "paper_site_list.json"
            entries = [{
                "paper_list_index": index,
                "trace_class_id": index,
                "trace_class_id_binding": "user_attested_zero_based_appendix_index",
                "domain": "site{}.test".format(index)}
                for index in range(75)]
            site_list_path.write_text(json.dumps({
                "status": "user_attested_binding_to_current_trace_labels",
                "entries": entries}), encoding="utf-8")
            site_list_sha = v3.sha256_file(site_list_path)
            class_map = {str(index): "http://site{}.test".format(index)
                         for index in range(75)}
            attestation = root / "dataset_identity_attestation.json"
            record = {
                "schema_version": 1,
                "attestation_type": "user_confirmed_dataset_identity",
                "confirmed_by_user": True,
                "dataset_doi": v3.ATTESTED_SOURCE_DOI,
                "class_id_binding_rule":
                    "trace_class_id_equals_zero_based_paper_appendix_index",
                "local_domains": {
                    "F": "dataset/tor_fiber", "S": "dataset/tor_starlink"},
                "class_id_range": [0, 74],
                "url_mapping_convention": "http://<Appendix A domain>/",
                "paper_source": {"site_list_sha256": site_list_sha},
                "authorization": {
                    "allow_training_admission": True,
                    "allow_unresolved_semantics": True,
                    "scientific_fidelity_claim": False}}
            attestation.write_text(json.dumps(record), encoding="utf-8")
            source_audit_path = root / "source_audit.json"
            source_audit_path.write_text(json.dumps({
                "status": v3.ATTESTED_SOURCE_AUDIT_STATUS,
                "user_attestation": {
                    "type": "user_confirmed_dataset_identity",
                    "path": str(attestation),
                    "sha256": v3.sha256_file(attestation),
                    "dataset_doi": v3.ATTESTED_SOURCE_DOI,
                    "class_id_binding_rule":
                        "trace_class_id_equals_zero_based_paper_appendix_index",
                    "site_list_path": str(site_list_path),
                    "site_list_sha256": site_list_sha,
                    "confirmed_by_user": True,
                    "authorization": record["authorization"]},
                "common_class_ids": [str(index) for index in range(75)],
                "common_class_map": class_map,
                "class_mapping_sha256": v3.canonical_sha256(class_map),
                "training_admission":
                    "allowed_with_user_attestation_and_semantic_caveats",
                "unresolved_semantics": ["F.packet_unit remains unknown"]
            }), encoding="utf-8")
            manifest_path = root / "dataset_manifest.json"
            manifest_path.write_text(json.dumps({
                "source_audit_sha256": v3.sha256_file(source_audit_path),
                "artifact_root": "dataset",
                "protocol_config": {
                    "path": "runtime_config.json",
                    "sha256": v3.sha256_file(config_path)},
                "samples": []}), encoding="utf-8")
            result = v3.audit_candidate_manifest(source_audit_path, manifest_path)
            self.assertNotIn("F/S source audit status is not accepted: "
                             + v3.ATTESTED_SOURCE_AUDIT_STATUS, result["errors"])
            self.assertNotIn("F/S source audit user attestation is missing, changed, or invalid",
                             result["errors"])
            self.assertEqual(v3.ATTESTED_SOURCE_AUDIT_STATUS,
                             result["source_audit_status"])
            self.assertEqual(["F.packet_unit remains unknown"],
                             result["source_semantic_caveats"])
            source_audit = v3.load_json(source_audit_path)
            source_audit["common_class_map"]["0"] = "http://wrong.test"
            source_audit_path.write_text(json.dumps(source_audit), encoding="utf-8")
            manifest = v3.load_json(manifest_path)
            manifest["source_audit_sha256"] = v3.sha256_file(source_audit_path)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            tampered = v3.audit_candidate_manifest(source_audit_path, manifest_path)
            self.assertIn("F/S source audit user attestation is missing, changed, or invalid",
                          tampered["errors"])


class RouteNatPlanTests(unittest.TestCase):
    def test_route_tool_matches_frozen_v3_network_config(self):
        config_path, digest = route_nat.validate_runtime_config()
        self.assertEqual(v3.DEFAULT_CONFIG.resolve(), config_path)
        self.assertEqual(64, len(digest))
        endpoint = v3.load_json(config_path)["network"]["fixed_object_endpoint"]
        self.assertEqual("9.27.27.20", endpoint["address"])
        self.assertEqual("B27-default", endpoint["interface"])

    def test_plan_uses_gre_capture_and_gs27_nat(self):
        plan = route_nat.build_plan("a" * 64, "b" * 64,
                                    "9.26.26.10", "9.27.27.10")
        self.assertEqual("wf-gre0", plan["client"]["capture_interface"])
        self.assertEqual("via 10.255.253.2 dev wf-gre0",
                         plan["client"]["fixed_object_endpoint_route"])
        self.assertEqual("B27-default", plan["egress"]["uplink_interface"])
        self.assertEqual("10.255.253.0/30", plan["egress"]["source_nat"])

    def test_exact_endpoint_route_snapshot_excludes_less_specific_routes(self):
        result = subprocess.CompletedProcess(
            ["docker", "exec"], 0,
            "default via 9.1.7.60 dev B26-eth1\n"
            "9.27.27.0/24 via 9.1.7.60 dev B26-eth1\n"
            "9.27.27.20 via 9.1.7.60 dev B26-eth1 proto bird\n", "")
        with patch.object(route_nat, "docker_exec", return_value=result):
            self.assertEqual(
                ["9.27.27.20 via 9.1.7.60 dev B26-eth1 proto bird"],
                route_nat._exact_ipv4_host_routes("a" * 12, "9.27.27.20"))

    def test_cleanup_restores_exact_endpoint_route(self):
        state = {
            "schema_version": 1,
            "protocol_id": "starrynet-browser-tor-route-nat-v3",
            "client_container_id": "a" * 12,
            "egress_container_id": "b" * 12,
            "fixed_object_endpoint": {"address": "9.27.27.20"},
            "before": {"client": {
                "fixed_object_endpoint_host_routes": [
                    "9.27.27.20 via 9.1.7.60 dev B26-eth1 proto bird"]}},
            "mutations": {"client_endpoint_host_route_changed": True}}
        result = subprocess.CompletedProcess(["docker", "exec"], 0, "", "")
        with patch.object(route_nat, "_assert_starrynet_container"):
            with patch.object(route_nat, "docker_exec", return_value=result) as run:
                self.assertEqual([], route_nat.cleanup_state(state))
        commands = [call[0][1] for call in run.call_args_list]
        self.assertIn("ip -4 route del 9.27.27.20/32", commands)
        self.assertIn(
            "ip -4 route replace 9.27.27.20 via 9.1.7.60 dev B26-eth1 proto bird",
            commands)
        self.assertFalse(state["mutations"]["client_endpoint_host_route_changed"])

    def test_host_proxy_gateway_is_pinned_to_gre_and_route_is_recorded(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "route_state.json"
            state_path.write_text(json.dumps({
                "schema_version": 1,
                "protocol_id": "starrynet-browser-tor-route-nat-v3",
                "installed": True,
                "client_container_id": "a" * 12,
                "mutations": {},
                "route_checks": {},
            }), encoding="utf-8")
            before = {"dev": "B26-eth1", "via": "9.1.7.60",
                      "raw": "9.27.27.1 via 9.1.7.60 dev B26-eth1 proto bird"}
            after = {"dev": "wf-gre0", "via": "10.255.253.2",
                     "raw": "9.27.27.1 via 10.255.253.2 dev wf-gre0"}
            result = subprocess.CompletedProcess(["docker", "exec"], 0, "", "")
            with patch.object(route_nat, "_assert_starrynet_container"):
                with patch.object(route_nat, "_route", side_effect=[before, after]):
                    with patch.object(route_nat, "_exact_ipv4_host_routes",
                                      return_value=[before["raw"]]):
                        with patch.object(route_nat, "docker_exec",
                                          return_value=result) as docker_exec:
                            override = route_nat.ensure_client_host_route_via_gre(
                                state_path, "9.27.27.1")
            saved = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual("B26-eth1", override["before"]["dev"])
            self.assertEqual("wf-gre0", override["route"]["dev"])
            self.assertTrue(override["changed"])
            self.assertTrue(saved["client_host_route_overrides"][
                "9.27.27.1"]["changed"])
            self.assertIn(
                "ip -4 route replace 9.27.27.1/32 via 10.255.253.2 dev wf-gre0",
                [call[0][1] for call in docker_exec.call_args_list])

    def test_cleanup_restores_host_proxy_gateway_route(self):
        state = {
            "schema_version": 1,
            "protocol_id": "starrynet-browser-tor-route-nat-v3",
            "client_container_id": "a" * 12,
            "egress_container_id": "b" * 12,
            "client_host_route_overrides": {
                "9.27.27.1": {
                    "before_host_routes": [
                        "9.27.27.1 via 9.1.7.60 dev B26-eth1 proto bird"],
                    "changed": True}},
            "mutations": {"client_host_route_overrides": {
                "9.27.27.1": True}},
            "before": {"client": {"rp_filter": []},
                       "egress": {"rp_filter": [], "ip_forward": "0"}},
        }
        result = subprocess.CompletedProcess(["docker", "exec"], 0, "", "")
        with patch.object(route_nat, "_assert_starrynet_container"):
            with patch.object(route_nat, "docker_exec", return_value=result) as run:
                self.assertEqual([], route_nat.cleanup_state(state))
        commands = [call[0][1] for call in run.call_args_list]
        self.assertIn("ip -4 route del 9.27.27.1/32", commands)
        self.assertIn(
            "ip -4 route replace 9.27.27.1 via 9.1.7.60 dev B26-eth1 proto bird",
            commands)
        self.assertFalse(state["client_host_route_overrides"][
            "9.27.27.1"]["changed"])
        self.assertFalse(state["mutations"]["client_host_route_overrides"][
            "9.27.27.1"])

    def test_plan_rejects_unsafe_container_or_ip(self):
        with self.assertRaises(ValueError):
            route_nat.build_plan("not-a-container", "b" * 64,
                                  "9.26.26.10", "9.27.27.10")
        with self.assertRaises(ValueError):
            route_nat.build_plan("a" * 64, "b" * 64,
                                  "9.26.26.10", "not-an-ip")

    def test_install_refuses_containers_outside_starrynet_service(self):
        result = subprocess.CompletedProcess(
            ["docker", "inspect"], 0, "unrelated-service\n", "")
        with patch.object(route_nat.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(RuntimeError, "outside the StarryNet"):
                route_nat._assert_starrynet_container("a" * 12)

    def test_preexisting_firewall_chain_is_not_removed_during_rollback(self):
        state = {
            "schema_version": 1,
            "protocol_id": "starrynet-browser-tor-route-nat-v3",
            "client_container_id": "a" * 12,
            "egress_container_id": "b" * 12,
            "before": {"client": {"rp_filter": []},
                       "egress": {"rp_filter": [], "ip_forward": "0"}},
            "mutations": {
                "rp_filter_changed": False,
                "client_tunnel_created": False,
                "egress_tunnel_created": False,
                "ip_forward_changed": False,
                "forward_chain_created": False,
                "forward_hook_inserted": False,
                "nat_chain_created": False,
                "nat_hook_inserted": False,
                "client_ipv4_routes_changed": False,
                "client_ipv6_routes_changed": False}}
        existing_chain = subprocess.CompletedProcess(
            ["docker", "exec"], 0, "-N WFV3_FWD\n", "")
        with patch.object(route_nat, "docker_exec", return_value=existing_chain):
            with self.assertRaises(RuntimeError):
                route_nat._install_iptables("b" * 12, state, Path("unused-state.json"))
        with patch.object(route_nat, "_assert_starrynet_container"):
            with patch.object(route_nat, "_remove_iptables") as remove:
                self.assertEqual([], route_nat.cleanup_state(state))
                remove.assert_not_called()


class CaptureShutdownTests(unittest.TestCase):
    def test_tcpdump_counters_distinguish_written_and_filtered_packets(self):
        counts = fixed_object._tcpdump_counts(
            "100 packets captured\n110 packets received by filter\n"
            "0 packets dropped by kernel\n")
        self.assertEqual({"captured": 100, "received_by_filter": 110,
                          "dropped_by_kernel": 0}, counts)

    def test_stop_capture_waits_for_tcpdump_process_exit(self):
        capture = {"container": "a" * 12, "label": "client",
                   "pid": "/tmp/client.pid", "pcap": "/tmp/client.pcap"}
        results = [
            subprocess.CompletedProcess(["docker", "exec"], 0, "", ""),
            subprocess.CompletedProcess(["docker", "exec"], 1, "", "no process"),
        ]
        with patch.object(fixed_object, "docker_exec", return_value="24") as docker_exec:
            with patch.object(fixed_object, "run_command", side_effect=results) as run:
                with patch.object(fixed_object.time, "sleep"):
                    fixed_object.stop_capture(capture)
        self.assertTrue(capture["stopped"])
        self.assertEqual(2, run.call_count)
        self.assertEqual(2, docker_exec.call_count)


class LinkProfileTests(unittest.TestCase):
    def test_netem_combines_orbit_delay_and_one_way_scenario_damage(self):
        args = netem_arguments(12.5, {
            "rate_mbps": 120,
            "extra_one_way_delay_ms": 3.5,
            "jitter_ms": 2,
            "loss_percent": 0.5,
            "queue_packets": 250,
        })
        self.assertEqual(["delay", "16ms", "2ms", "distribution", "normal",
                          "loss", "0.5%", "rate", "120mbit", "limit", "250"],
                         args)

    def test_direction_mapping_covers_ground_station_return_path(self):
        self.assertEqual(("satellite_ground", "satellite_to_ground",
                          "ground_to_satellite"),
                         direction_for_nodes(4, 25, 25))
        self.assertEqual(("satellite_ground", "ground_to_satellite",
                          "satellite_to_ground"),
                         direction_for_nodes(25, 4, 25))

    def test_initial_link_builder_emits_directional_netem_parameters(self):
        profile = v3.starrynet_link_profile(v3.load_json(v3.DEFAULT_CONFIG))
        with patch.object(sn_orchestrater, "sn_checked_system") as checked:
            sn_orchestrater.sn_apply_link_qdisc(
                "a" * 12, "B26-eth7", 12.5, 5, 0,
                profile["inter_satellite"]["a_to_b"])
        command = checked.call_args[0][0]
        self.assertIn("qdisc replace", command)
        self.assertIn("rate 5000mbit", command)
        self.assertIn("limit 1000", command)

    def test_dynamic_delay_update_keeps_ground_link_asymmetry(self):
        profile = {
            "inter_satellite": {
                "a_to_b": {"rate_mbps": 500, "extra_one_way_delay_ms": 0,
                            "jitter_ms": 0, "loss_percent": 0, "queue_packets": 200},
                "b_to_a": {"rate_mbps": 500, "extra_one_way_delay_ms": 0,
                            "jitter_ms": 0, "loss_percent": 0, "queue_packets": 200}},
            "satellite_ground": {
                "satellite_to_ground": {
                    "rate_mbps": 120, "extra_one_way_delay_ms": 3,
                    "jitter_ms": 2, "loss_percent": 0.5, "queue_packets": 250},
                "ground_to_satellite": {
                    "rate_mbps": 240, "extra_one_way_delay_ms": 5,
                    "jitter_ms": 4, "loss_percent": 1, "queue_packets": 500}}}
        with patch.object(sn_orchestrater.subprocess, "check_output",
                          return_value="qdisc root netem"):
            with patch.object(sn_orchestrater.subprocess, "run") as run:
                sn_orchestrater.sn_delay_change(
                    1, 25, 12, ["c{}".format(i) for i in range(27)], 25, profile)
        first = run.call_args_list[0][0][0]
        second = run.call_args_list[1][0][0]
        self.assertIn("15ms", first)
        self.assertIn("120mbit", first)
        self.assertIn("17ms", second)
        self.assertIn("240mbit", second)
        self.assertIn("500", second)

    def test_dynamic_gsl_creation_uses_profiled_qdisc_and_checked_remote_command(self):
        profile = v3.starrynet_link_profile(v3.load_json(v3.DEFAULT_CONFIG))
        downlink = profile["satellite_ground"]["satellite_to_ground"]
        uplink = profile["satellite_ground"]["ground_to_satellite"]
        with patch.object(sn_utils, "sn_remote_checked_cmd") as checked:
            sn_utils._sn_apply_gsl_profile(
                object(), "a" * 12, "B1-eth26", 12.5, 5, 0, downlink)
            sn_utils._sn_apply_gsl_profile(
                object(), "b" * 12, "B26-eth1", 12.5, 5, 0, uplink)
        down_command = checked.call_args_list[0][0][1]
        up_command = checked.call_args_list[1][0][1]
        self.assertIn("qdisc replace", down_command)
        self.assertIn("delay 12.5ms", down_command)
        self.assertIn("rate 5000mbit", down_command)
        self.assertIn("B26-eth1", up_command)
        self.assertIn("limit 1000", up_command)


class SimulationClockTests(unittest.TestCase):
    def test_profile_run_records_logical_utc_and_monotonic_anchor(self):
        with tempfile.TemporaryDirectory() as tmp:
            thread = object.__new__(sn_utils.sn_Emulation_Start_Thread)
            thread.link_profile = {"engineering_baseline": True}
            thread.configuration_file_path = tmp
            thread.file_path = "v3-run"
            thread.record_simulation_clock(
                120, "topology_change_applied", 6000.0, 0.25)
            path = Path(tmp) / "v3-run" / "simulation_clock.jsonl"
            row = json.loads(path.read_text(encoding="utf-8").strip())
            self.assertEqual(120, row["logical_time_seconds"])
            self.assertEqual("topology_change_applied", row["event"])
            self.assertEqual(6000.0, row["scheduled_monotonic_seconds"])
            self.assertEqual(0.25, row["scheduler_lag_seconds"])
            self.assertGreater(row["monotonic_seconds"], 0)
            self.assertIn("+00:00", row["utc"])


if __name__ == "__main__":
    unittest.main()

"""Strict event evidence checks and client trace export for Research 2.

This module deliberately depends only on the Python standard library so it
can run on the project's Python 3.6 hosts without importing the replay stack.
"""

from __future__ import division

import math


_ROLE_EXPECTATIONS = {
    "client": {1: "send", -1: "recv"},
    "remote": {1: "recv", -1: "send"},
}


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _identity_value(row, records, field, errors, endpoint):
    """Return an endpoint identity, accepting a row or its event records."""
    values = []
    if field in row and row[field] is not None:
        values.append(("row", row[field]))
    for index, record in enumerate(records):
        if isinstance(record, dict) and field in record and record[field] is not None:
            values.append(("record {0}".format(index), record[field]))
    if not values:
        errors.append("{0} missing required {1} evidence".format(endpoint, field))
        return None
    distinct = []
    for location, value in values:
        if value not in distinct:
            distinct.append(value)
    if len(distinct) != 1:
        errors.append("{0} has inconsistent {1} values: {2}".format(
            endpoint, field, ", ".join(str(value) for value in distinct)))
    value = distinct[0]
    if field == "sample_id" and (not isinstance(value, str) or not value):
        errors.append("{0} has invalid sample_id".format(endpoint))
    if field == "sample_token" and not _is_int(value):
        errors.append("{0} has invalid sample_token".format(endpoint))
    return value


def _validate_source_events(source_events, errors):
    if not isinstance(source_events, (list, tuple)):
        errors.append("source_events must be a list or tuple")
        return []
    if not source_events:
        errors.append("source_events must not be empty")
        return []
    normalized = []
    seen = set()
    for index, event in enumerate(source_events):
        if not isinstance(event, dict):
            errors.append("source event {0} is not an object".format(index))
            continue
        sequence = event.get("sequence")
        direction = event.get("direction")
        offset_ns = event.get("offset_ns")
        if not _is_int(sequence) or sequence < 0:
            errors.append("source event {0} has invalid sequence".format(index))
            continue
        if sequence in seen:
            errors.append("source has duplicate sequence {0}".format(sequence))
        seen.add(sequence)
        if direction not in (-1, 1) or not _is_int(direction):
            errors.append("source event {0} has invalid direction".format(index))
            continue
        if not _is_int(offset_ns) or offset_ns < 0:
            errors.append("source event {0} has invalid offset_ns".format(index))
            continue
        normalized.append({"sequence": sequence, "direction": direction,
                           "offset_ns": offset_ns})
    sequences = [event["sequence"] for event in normalized]
    if sequences != list(range(len(source_events))):
        errors.append("source sequences must be contiguous and ordered from 0")
    previous_offset = None
    for event in normalized:
        if previous_offset is not None and event["offset_ns"] < previous_offset:
            errors.append("source offsets must be nondecreasing")
            break
        previous_offset = event["offset_ns"]
    return normalized


def _validate_endpoint(row, endpoint, source_events, payload_bytes, errors):
    if not isinstance(row, dict):
        errors.append("{0} sample_done row is missing or invalid".format(endpoint))
        return [], None, None
    records = row.get("records")
    if not isinstance(records, list):
        errors.append("{0} records must be a list".format(endpoint))
        records = []
    for error_field in ("send_errors", "receive_errors"):
        endpoint_errors = row.get(error_field)
        if not isinstance(endpoint_errors, list):
            errors.append("{0} {1} must be a list".format(endpoint, error_field))
        elif endpoint_errors:
            errors.append("{0} reports {1}: {2}".format(
                endpoint, error_field, endpoint_errors))

    sample_id = _identity_value(row, records, "sample_id", errors, endpoint)
    sample_token = _identity_value(row, records, "sample_token", errors, endpoint)
    expected = {}
    for event in source_events:
        sequence = event["sequence"]
        action = _ROLE_EXPECTATIONS[endpoint][event["direction"]]
        expected[sequence] = (event["direction"], event["offset_ns"], action)

    by_sequence = {}
    for index, record in enumerate(records):
        prefix = "{0} record {1}".format(endpoint, index)
        if not isinstance(record, dict):
            errors.append(prefix + " is not an object")
            continue
        sequence = record.get("sequence")
        if not _is_int(sequence) or sequence < 0:
            errors.append(prefix + " has invalid sequence")
            continue
        if sequence in by_sequence:
            errors.append("{0} has duplicate sequence {1}".format(endpoint, sequence))
        else:
            by_sequence[sequence] = record
        if sequence not in expected:
            errors.append("{0} has extra sequence {1}".format(endpoint, sequence))
            continue
        direction, offset_ns, action = expected[sequence]
        record_direction = record.get("direction")
        if not _is_int(record_direction) or record_direction != direction:
            errors.append("{0} sequence {1} direction mismatch".format(endpoint, sequence))
        if record.get("action") != action:
            errors.append("{0} sequence {1} action mismatch".format(endpoint, sequence))
        scheduled = record.get("scheduled_offset_ns")
        if not _is_int(scheduled) or scheduled != offset_ns:
            errors.append("{0} sequence {1} scheduled offset mismatch".format(
                endpoint, sequence))
        observed = record.get("observed_ns")
        if not _is_int(observed) or observed < 0:
            errors.append("{0} sequence {1} has invalid observed_ns".format(
                endpoint, sequence))
        if record.get("bytes") != payload_bytes or not _is_int(record.get("bytes")):
            errors.append("{0} sequence {1} payload byte count mismatch".format(
                endpoint, sequence))
        if action == "send":
            completed = record.get("send_completed_ns")
            if not _is_int(completed) or completed < 0:
                errors.append("{0} sequence {1} has invalid send_completed_ns".format(
                    endpoint, sequence))
            elif _is_int(observed) and completed < observed:
                errors.append("{0} sequence {1} send completed before it started".format(
                    endpoint, sequence))
        for identity_field, expected_identity in (("sample_id", sample_id),
                                                  ("sample_token", sample_token)):
            if identity_field in record and record[identity_field] is not None:
                if expected_identity is not None and record[identity_field] != expected_identity:
                    errors.append("{0} sequence {1} {2} mismatch".format(
                        endpoint, sequence, identity_field))
    for sequence in expected:
        if sequence not in by_sequence:
            errors.append("{0} missing sequence {1}".format(endpoint, sequence))
    return records, sample_id, sample_token


def verify_events(source_events, client_row, remote_row, payload_bytes=512):
    """Verify exact source event delivery and endpoint evidence.

    ``observed_ns`` and ``send_completed_ns`` are monotonic observations; this
    checker validates their form and ordering without equating them to the
    scheduled source offsets.
    """
    errors = []
    if not _is_int(payload_bytes) or payload_bytes <= 0:
        errors.append("payload_bytes must be a positive integer")
        payload_bytes = 512
    normalized_source = _validate_source_events(source_events, errors)
    client_records, client_id, client_token = _validate_endpoint(
        client_row, "client", normalized_source, payload_bytes, errors)
    remote_records, remote_id, remote_token = _validate_endpoint(
        remote_row, "remote", normalized_source, payload_bytes, errors)
    if client_id is not None and remote_id is not None and client_id != remote_id:
        errors.append("client and remote sample_id differ")
    if client_token is not None and remote_token is not None and client_token != remote_token:
        errors.append("client and remote sample_token differ")
    return {
        "passed": not errors,
        "errors": errors,
        "event_count": len(normalized_source),
        "client_record_count": len(client_records),
        "remote_record_count": len(remote_records),
        "sample_id": client_id if client_id is not None else remote_id,
        "sample_token": client_token if client_token is not None else remote_token,
    }


def build_client_trace(client_row):
    """Export client send/receive application events to two-column trace text.

    Returns ``(trace_text, mapping_records)``.  Each exported timestamp comes
    from the corresponding endpoint observation (send completion for sends,
    receive observation for receives), normalized relative to the first event.
    """
    if not isinstance(client_row, dict):
        raise ValueError("client_row must be an object")
    records = client_row.get("records")
    if not isinstance(records, list):
        raise ValueError("client records must be a list")
    for error_field in ("send_errors", "receive_errors"):
        if client_row.get(error_field):
            raise ValueError("client row reports {0}".format(error_field))
    selected = []
    seen_sequences = set()
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ValueError("client record {0} is not an object".format(index))
        direction = record.get("direction")
        action = record.get("action")
        if (not _is_int(direction) or
                (direction, action) not in ((1, "send"), (-1, "recv"))):
            raise ValueError("client record {0} has unexpected direction/action".format(index))
        sequence = record.get("sequence")
        offset_ns = record.get("scheduled_offset_ns")
        observed_ns = record.get("observed_ns")
        if not _is_int(sequence) or sequence < 0:
            raise ValueError("client record {0} has invalid sequence".format(index))
        if sequence in seen_sequences:
            raise ValueError("client records contain duplicate sequence {0}".format(sequence))
        seen_sequences.add(sequence)
        if not _is_int(offset_ns) or offset_ns < 0:
            raise ValueError("client record {0} has invalid scheduled_offset_ns".format(index))
        if not _is_int(observed_ns) or observed_ns < 0:
            raise ValueError("client record {0} has invalid observed_ns".format(index))
        if action == "send":
            selected_ns = record.get("send_completed_ns")
            if not _is_int(selected_ns) or selected_ns < observed_ns:
                raise ValueError("client record {0} has invalid send completion".format(index))
        else:
            selected_ns = observed_ns
        selected.append({"sequence": sequence, "action": action,
                         "direction": direction, "selected_ns": selected_ns,
                         "scheduled_offset_ns": offset_ns})
    if not selected:
        raise ValueError("client row contains no exportable application events")
    selected.sort(key=lambda row: (row["selected_ns"], row["sequence"]))
    first_ns = selected[0]["selected_ns"]
    trace_lines = []
    mapping_records = []
    previous_timestamp = 0.0
    for record in selected:
        try:
            timestamp = (record["selected_ns"] - first_ns) / 1e9
        except OverflowError:
            raise ValueError("selected client event time is outside finite range")
        if not math.isfinite(timestamp) or timestamp < 0 or timestamp < previous_timestamp:
            raise ValueError("selected client event times do not form a valid trace")
        trace_lines.append("{0:.9f}\t{1}\n".format(timestamp, record["direction"]))
        mapping_records.append({
            "sequence": record["sequence"],
            "action": record["action"],
            "direction": record["direction"],
            "selected_ns": record["selected_ns"],
            "timestamp": timestamp,
            "scheduled_offset_ns": record["scheduled_offset_ns"],
        })
        previous_timestamp = timestamp
    return "".join(trace_lines), mapping_records

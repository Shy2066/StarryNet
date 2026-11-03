"""Directional qdisc profile helpers shared by local and remote StarryNet code."""
import math


PROFILE_FIELDS = ("rate_mbps", "extra_one_way_delay_ms", "jitter_ms",
                  "loss_percent", "queue_packets")


def validate_profile(profile):
    if not isinstance(profile, dict):
        raise ValueError("link profile must be an object")
    errors = []
    for link_type, directions in (
            ("inter_satellite", ("a_to_b", "b_to_a")),
            ("satellite_ground", ("satellite_to_ground", "ground_to_satellite"))):
        link = profile.get(link_type)
        if not isinstance(link, dict):
            errors.append("missing {} profile".format(link_type))
            continue
        for direction in directions:
            values = link.get(direction)
            if not isinstance(values, dict):
                errors.append("missing {}.{} profile".format(link_type, direction))
                continue
            for field in PROFILE_FIELDS:
                value = values.get(field)
                if (not isinstance(value, (int, float)) or isinstance(value, bool)
                        or not math.isfinite(value) or value < 0):
                    errors.append("{}.{}.{} must be finite and nonnegative".format(
                        link_type, direction, field))
            rate = values.get("rate_mbps")
            if isinstance(rate, (int, float)) and not isinstance(rate, bool) and rate <= 0:
                errors.append("{}.{}.rate_mbps must be positive".format(
                    link_type, direction))
            loss = values.get("loss_percent")
            if isinstance(loss, (int, float)) and loss > 100:
                errors.append("{}.{}.loss_percent cannot exceed 100".format(
                    link_type, direction))
            queue = values.get("queue_packets")
            if (not isinstance(queue, int) or isinstance(queue, bool)
                    or queue < 1):
                errors.append("{}.{}.queue_packets must be a positive integer".format(
                    link_type, direction))
    if errors:
        raise ValueError("; ".join(errors))
    return profile


def profile_for(profile, link_type, direction):
    if profile is None:
        return None
    validate_profile(profile)
    return profile[link_type][direction]


def _number(value):
    if int(value) == value:
        return str(int(value))
    return ("%.6f" % float(value)).rstrip("0").rstrip(".")


def netem_arguments(base_delay_ms, profile):
    """Build netem argv; orbital delay and configured extra delay are additive."""
    if (not isinstance(base_delay_ms, (int, float))
            or not math.isfinite(base_delay_ms) or base_delay_ms < 0):
        raise ValueError("base delay must be finite and nonnegative")
    values = profile or {}
    extra = values.get("extra_one_way_delay_ms", 0)
    jitter = values.get("jitter_ms", 0)
    rate = values.get("rate_mbps")
    loss = values.get("loss_percent")
    queue = values.get("queue_packets")
    delay = float(base_delay_ms) + float(extra)
    arguments = ["delay", _number(delay) + "ms"]
    if float(jitter) > 0:
        arguments.extend([_number(jitter) + "ms", "distribution", "normal"])
    if loss is not None:
        arguments.extend(["loss", _number(loss) + "%"])
    if rate is not None:
        arguments.extend(["rate", _number(rate) + "mbit"])
    if queue is not None:
        arguments.extend(["limit", str(int(queue))])
    return arguments


def direction_for_nodes(first_index, second_index, satellite_count):
    """Return link type and qdisc direction from the first node to the second."""
    first_satellite = int(first_index) < int(satellite_count)
    second_satellite = int(second_index) < int(satellite_count)
    if first_satellite and second_satellite:
        return "inter_satellite", "a_to_b", "b_to_a"
    if first_satellite and not second_satellite:
        return "satellite_ground", "satellite_to_ground", "ground_to_satellite"
    if not first_satellite and second_satellite:
        return "satellite_ground", "ground_to_satellite", "satellite_to_ground"
    raise ValueError("StarryNet link profiles require at least one satellite endpoint")

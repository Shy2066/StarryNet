#!/usr/bin/env python3
"""Remove only StarryNet-owned resources; legacy unlabelled networks are retained."""
from starrynet.sn_orchestrater import sn_stop_emulation


def cleanup():
    sn_stop_emulation()


if __name__ == '__main__':
    cleanup()

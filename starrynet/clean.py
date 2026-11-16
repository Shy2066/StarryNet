#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""Remove only the StarryNet Docker resources owned by this run."""

try:
    from starrynet.sn_orchestrater import sn_stop_emulation
except ImportError:
    from sn_orchestrater import sn_stop_emulation


def cleanup():
    print("Cleaning resources owned by STARRYNET_OWNER/STARRYNET_SERVICE...")
    sn_stop_emulation()


if __name__ == "__main__":
    cleanup()

# StarryNet P2 controlled Tor smoke

P2 extends the P0/P1 25-satellite, two-ground-station topology with one private Tor test network, a fixed static page, and two endpoint captures. The Tor client shares GS26's network namespace. Its Guard address is `9.27.27.11`, attached to the local `GS_27` bridge behind GS27; the client route to it must resolve through a `B26-eth*` satellite interface. Guard, Middle, Exit, and three private directory authorities use distinct Tor identities, ports, and GS27 IP aliases (`9.27.27.11`–`9.27.27.16`). This keeps every relay separately addressable in the test consensus. The Exit advertises HTTP/HTTPS capability so the test authority includes it as an Exit in its microdescriptor consensus. A relay-side OUTPUT firewall allows Tor traffic only to those six private test addresses and new page requests only to the fixed server on the run's internal Docker bridge.

The three relay processes and three authorities run in one disposable Tor sidecar attached to GS27's `GS_27` network and the isolated P2 bridge. Their Tor identities, IP aliases, keys, data directories, and OR ports are separate. The client-to-Guard connection crosses the StarryNet satellite access path. The other test relay processes share the sidecar network namespace; their local relay-to-relay links are not separate satellite paths. The Exit-to-server TCP connection uses the isolated P2 bridge. This is an engineering smoke for controlled circuit setup, a real Tor stream, the GS26 access path, PCAP evidence, and cleanup; it does not claim a physically distributed Tor relay network.

## Build and run

```bash
cd /home/shy/Project/StarryNet
python -u tools/p2_tor_smoke.py plan
python -u tools/p2_tor_smoke.py build-image
python -u tools/p2_tor_smoke.py preflight
python -u tools/p2_tor_smoke.py run
```

The image is separate from `lwsen/starlab_node:1.0`; it pins Debian Tor `0.4.9.11-0+deb12u1` and Stem `1.8.1-2.1`, and includes `iproute2`, `iptables`, and `tcpdump`. The Chutney source snapshot is stored and checksum-verified in `tools/p2_tor`, so image builds do not depend on a live GitHub download. Each run copies the complete Chutney source and checksums into its artifact directory so the actual source used is frozen. `run` uses the existing `.p0.lock`, one-node Swarm preflight, StarryNet worker-error propagation, frozen run sources, labelled helper resources, the existing scoped StarryNet cleanup, and before/after Docker inventories.

The run bootstraps a private Chutney network, explicitly creates and records a Guard→Middle→Exit circuit, then downloads the same static HTML object three times: once in a stable initialized topology, once before the first GS27 handover, and once after it. The current 100-second topology has no GS26 handover and one GS27 handover at second 53; GS27 is the gateway on this path. The two dynamic requests use the same controlled path when the circuit remains built. If Tor has to rebuild after a handover, the visit record captures the new circuit ID, path, status, and rebuild flag. Each visit records the GS26 route and the elapsed time.

## Artifacts and gates

Each run writes to `artifacts/p2_tor/<UTC timestamp>/` and retains `summary.json`, `manifest.json`, the per-run StarryNet config and topology, a source snapshot and SHA-256 manifest, the Tor client torrc, public relay/authority config and logs, controller events, the fixed fixture, each downloaded page, and both PCAPs. The client PCAP is captured on the route-selected GS26 `B26-eth*` satellite interface and filtered to the Guard ORPort; the exit/server PCAP is captured on the fixed server interface and filtered to TCP port 18080. The client capture must show payload to the Guard while the static HTTP request and response remain absent. The server capture must show the cleartext page request and HTTP 200 for every successful page fetch. The applications also check HTTP status, byte size, and SHA-256.

`p2_completed=true` requires a built controlled circuit, a valid stable page, useful PCAPs at both endpoints, route evidence on a satellite interface for each scheduled visit, before/after-handover visit records, and a return to the exact startup Docker inventory. Handover fetches may succeed or fail; their outcomes and whether Tor rebuilt the circuit are retained as observations. `scientific_fidelity_verified` remains false because relay-to-relay physical diversity and real satellite calibration are outside this minimum loop.

Tor relay channels use TLS; the client PCAP is deliberately scoped to the Guard ORPort and checked for Tor payload without visible HTTP headers. The exit/server capture verifies the HTTP transaction after the Exit has accepted it. See the [Tor channel specification](https://spec.torproject.org/tor-spec/channels.html), [Stem circuit control example](https://stem.torproject.org/tutorials/to_russia_with_love.html), and [Chutney test-network guide](https://github.com/torproject/chutney/blob/main/README.md).

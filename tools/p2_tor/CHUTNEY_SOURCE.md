# Frozen Chutney source

`chutney-source.tar.gz` is the Chutney source tree used by the earlier P2
bootstrap attempt and archived under `artifacts/p2_tor/20261011T032745_693325Z`.
The build verifies every extracted file against `chutney-source.sha256` before
creating the experiment image. The archive SHA-256 is
`484afa9a1c1d56c76298db98fcf3f1bddbef98accf0309ea0f97d7886ef6da56`.

Keeping the fetched source snapshot in this experiment directory makes image
builds independent of a live GitHub download. The run artifact still copies the
source archive and checksum manifest into its own frozen source directory.

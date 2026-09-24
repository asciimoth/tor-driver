# Four directory authorities make the initial consensus reliable. The bridge
# authority publishes the private bridge descriptor. The client nodes are
# configuration templates only; container-run.sh starts launch phase 1.
Authority = Node(tag="a", authority=1, relay=1)
BridgeAuthority = Node(tag="bridgeauth", authority=1, bridgeauthority=1, relay=1)
ExitRelay = Node(tag="r", relay=1, exit=1)
Obfs4Bridge = Node(
    tag="br",
    bridge=1,
    launch_phase=2,
    pt_bridge=1,
    relay=1,
    pt_transport="obfs4",
    sandbox=0,
)
DirectClient = Node(tag="c", client=1, launch_phase=3)
Obfs4Client = Node(
    tag="bc",
    bridgeclient=1,
    client=1,
    launch_phase=3,
    pt_transport="obfs4",
    sandbox=0,
)

NODES = (
    Authority.getN(4)
    + BridgeAuthority.getN(1)
    + ExitRelay.getN(1)
    + Obfs4Bridge.getN(1)
    + DirectClient.getN(1)
    + Obfs4Client.getN(1)
)

ConfigureNodes(NODES)

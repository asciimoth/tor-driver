# Docker end-to-end tests

Run the deterministic Linux end-to-end suite with:

```sh
./e2e/run.sh
```

Use `./e2e/run.sh --smoke` to run only the direct-routing and obfs4 smoke
tests. The smoke mode also omits the privileged containment profile. GitHub CI
uses this mode; `just check` uses the complete suite.

The image starts a Chutney network with four directory authorities, one bridge
authority, one exit, and one private obfs4 bridge. Two `tor-driver` clients
then send HTTP traffic to a loopback server. One client uses the relays
directly. The other client can reach the network only through the generated
obfs4 bridge. The suite also checks actual circuit isolation, repeated outgoing
replacement, PT crashes, missing proxy support, wrong credentials, proxy
failure recovery, and obfs4 removal and replacement.

The test container runs with Docker network mode `none`. It has a loopback
interface for the private Tor network, but it cannot contact the public Tor
network or other hosts. A controlled PT tries direct IPv4, IPv6, and DNS
connections and records the OS denials. Chutney generates new authority and
bridge keys for each run. No bridge secrets are stored in the repository.

The script then runs a short privileged container profile with a normal parent
network. It launches Tor and the controlled PT through `ContainedSystem`. It
also uses `BestEffortSystem` to discover Tor and the PT in `PATH`, select the
container's `nobody` account, and select strict containment. Kernel nftables
counters must record denied IPv4, IPv6, and DNS attempts from each child cgroup.
The privileged container has its own network namespace; the rules do not change
the host network namespace.

The Dockerfile pins the Go base image, Tor Expert Bundle, Chutney commit, and
the exact lyrebird executable SHA-256.
The Debian packages supply Python dependencies, nftables, routing tools, and
`tor-gencert`. The default target is Linux amd64. Set
`TOR_DRIVER_E2E_PLATFORM` to override the Docker platform when a compatible Tor
Expert Bundle is added.

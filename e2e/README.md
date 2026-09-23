# Docker end-to-end tests

Run the deterministic Linux end-to-end suite with:

```sh
./e2e/run.sh
```

The image starts a Chutney network with four directory authorities, one bridge
authority, one exit, and one private obfs4 bridge. Two `tor-driver` clients
then send HTTP traffic to a loopback server. One client uses the relays
directly. The other client can reach the network only through the generated
obfs4 bridge.

The test container runs with Docker network mode `none`. It has a loopback
interface for the private Tor network, but it cannot contact the public Tor
network or other hosts. Chutney generates new authority and bridge keys for
each run. No bridge secrets are stored in the repository.

The Dockerfile pins the Go base image, Tor Expert Bundle, and Chutney commit.
The Debian packages supply Python dependencies and `tor-gencert`. The default
target is Linux amd64. Set `TOR_DRIVER_E2E_PLATFORM` to override the Docker
platform when a compatible Tor Expert Bundle is added.

# Architecture

`tor-driver` is a constrained Tor process driver. It owns one client-mode Tor
daemon and does not expose a general control-protocol or raw torrc interface.

## Trust boundaries

The embedding host owns `gobox.Service`, owner identities, templates, program
mappings, and sandbox policy. The library receives only
`gobox.OwnerSandboxes`. It acquires one slot and can select only approved
logical programs. It cannot request native host execution or weaken policy.

The acquired sandbox supplies:

- temporary and persistent files;
- child-visible paths for Tor configuration;
- the Tor command and complete process-tree lifecycle;
- loopback listeners for the upstream proxy and onion-service backends; and
- loopback dials for Tor control and SOCKS connections.

This is important for backends with a private network or filesystem view. Host
paths and host loopback are not assumed to be visible to Tor.

The outbound `gonnect.Network` stays outside this boundary. Tor connects only
to the authenticated loopback proxy. The proxy sends each requested relay or
managed-transport connection through the current outbound network.

## Launch contract

The default sandbox template and Tor program IDs are `tor`. The driver gives
the Tor program two typed path inputs: `defaults-torrc` and `torrc`. Protected
host policy converts these inputs to Tor arguments. Managed transports are
approved `gobox.ProgramID` values. The driver asks the sandbox for their
child-visible paths and writes only those paths to Tor configuration.

The command context lasts until shutdown. `Command.Kill`, context cancellation,
and `Sandbox.Close` must stop the complete command tree as required by the
`gobox` contract.

## Lifecycle

Startup creates private sandbox storage, starts the proxy, writes configuration,
starts Tor, authenticates with SAFECOOKIE, takes control ownership, subscribes
to events, verifies the proxy setting, and enables networking.

Shutdown first blocks outbound traffic and closes application resources. It
then requests Tor shutdown, kills the command after a bounded wait, removes
temporary files, and closes the sandbox. Persistent sandbox storage remains
subject to host policy.

Tor's `Sandbox` configuration option is its own optional seccomp feature. It is
not a substitute for the host `gobox` boundary.

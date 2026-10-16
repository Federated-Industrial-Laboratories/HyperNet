# Prepare a new network

`HyperNet runtime provision` prepares native transport identities, certificate
requests, certificates, clock configuration and authority replica inputs. These
commands start no workload and grant no membership or hosting capability. Keep
the issuer offline. Each authority operator generates and retains its own keys.
Never transfer a private identity or transport key to the issuer.

The commands require a maintained OpenSSL installation at `/usr/bin/openssl`.
They invoke fixed arguments without a shell. They use Ed25519 transport keys,
explicit IPv4 endpoints and certificates for both TLS server and client use.
Certificate issuance does not replace bootstrap acceptance or certificate pins.

Use persistent private directories with private ancestors. A new preparation is
published atomically into an unused destination. An interrupted unpublished
`Preparation...` directory is never accepted as an input. After confirming its
operation has stopped, remove that incomplete directory and retry the original
command. Preserve a published identity once its public request has been shared.
Do not regenerate a published identity to work around a mismatch.

## Identities and certificates

On the offline issuer:

```sh
HyperNet runtime provision issuer --directory /Private/TransportIssuer --days 365
```

Record and independently authenticate the returned `issuerDigest`. On each of
four authority hosts, select its reachable endpoint and prepare an identity:

```sh
HyperNet runtime provision identity --directory /Private/AuthorityIdentity \
  --address 192.0.2.10 --port 24443
```

`Identity.json`, `Service.key` and `Transport.key` stay on that host. `Service.key`
is the native32-byte role identity input for service setup; it requires no manual
key conversion. Authority and service roles still require separately generated
identities and distinct capability assignments. Share only the returned
`TransportRequest.json`, and authenticate its complete `requestDigest` through
an independent channel. The signed request binds the identity, transport key
and endpoint. Authenticate the operator's intended identity before accepting
that digest; a self-signature alone does not establish the operator's identity.

Issue the exact public request:

```sh
HyperNet runtime provision issue --directory /Private/TransportIssuer \
  --issuer-digest <authenticated-issuer-digest> \
  --request /Private/Requests/AuthorityOne.json \
  --request-digest <authenticated-request-digest> \
  --days 90 --output /Private/Peers/AuthorityOne.json
```

The returned peer file contains the public request, leaf certificate and issuer
certificate. Share it with all authority operators. Independently authenticate
each returned `peerDigest`. Private keys are absent from this file. Issuing a
certificate never changes the request's address, key or identity. Reissuing a
leaf changes its exact pin and therefore requires reviewed runtime configuration.

## Clock monitor and accepted bootstrap

On each authority host, configure the local read-only chrony monitor:

```sh
HyperNet runtime provision clock --directory /Private/ClockMonitor \
  --export-directory /Private/ClockObservations \
  --chronyc /usr/bin/chronyc --socket /run/chrony/chronyd.sock
HyperNet authority-clock initialise-export --directory /Private/ClockMonitor
HyperNet authority-clock monitor --directory /Private/ClockMonitor
```

Use the real local chrony socket. Keep the monitor running and retain its public
key separately from its private signing directory. A healthy current signed
observation is required by replica preparation and runtime activation.

Use the Suite's `Documentation/Networks.md` bootstrap ceremony to appoint the four identities
and their exact transport mappings, and to reserve each monitor key. Complete
the independent acceptance steps. Keep governance and recovery keys separate
from transport, monitor, operator and service identities. Authenticate the final
accepted bootstrap's complete digest with every operator.

## Replica inputs and activation

Each operator combines the accepted bootstrap with the four public peer files:

```sh
HyperNet runtime provision replica --directory /Private/AuthorityInputs \
  --identity-directory /Private/AuthorityIdentity \
  --bootstrap /Private/AcceptedBootstrap.cbor \
  --bootstrap-digest <authenticated-bootstrap-digest> \
  --peer /Private/Peers/AuthorityOne.json /Private/Peers/AuthorityTwo.json \
    /Private/Peers/AuthorityThree.json /Private/Peers/AuthorityFour.json \
  --peer-digest <peer-one-digest> <peer-two-digest> \
    <peer-three-digest> <peer-four-digest> \
  --clock-observation /Private/ClockObservations/ClockHealth.cbor \
  --monitor-key <reserved-local-monitor-key>
```

Preparation verifies the bootstrap acceptance, exact appointments, transport
keys, certificate chains, endpoint names and pins, local key pairs and current
signed clock observation. It writes `ReplicaConfig.json`, `Identity.json`,
`Bootstrap.cbor`, TLS inputs and four peer certificates in the private destination.
The output lists their paths. It neither edits firewall rules nor creates a
listener. Advertised endpoints must be reachable through the intended Internet
or private network path before activation.

Pass these paths to [runtime setup](Runtime.md), then review its resource and
endpoint preview and explicitly consent. Run each replica under its approved
session or managed policy. The network requires three of its four appointed
replicas for committed authority operations. Hosting roles have separate
[service setup and activation](ServiceRuntime.md); authority appointment does
not grant those roles.

# Manage IP addresses over an HTTPS-API
This small HTTP server allows adding and removing ip addresses from specific network interfaces on a linux system over an HTTPS-API. A newly added address will be advertised via a unsolicited ARP (IPv4) or Neigbour-Discovery (IPv6) message to the network. Requests are authenticated via TLS client certificates and guarded by policies, that control which addresses are allowed to be managed on which network interfaces.

## Usage
To build this program run `go build github.com/gerolf-vent/ipam-api/v2/cmd/ipam-api`. The server can be started by `ipam-api --config config.json`. Note that the server have to run with root permissions or better only with the `CAP_NET_ADMIN` and `CAP_NET_RAW` capability set.

### Configuration
When starting the server a configuration file must be passed via the cli argument `--config`. It's written in JSON with the following parameters:

| Name                         | Type            | Description                                                 |
| ---------------------------- | --------------- | ----------------------------------------------------------- |
| `port`                       | int             | Port to listen on                                           |
| `client_ca_certificate_path` | string          | Path to a TLS client ca certificate used for authentication |
| `server_certificate_path`    | string          | Path to a TLS server certificate                            |
| `server_certificate_path`    | string          | Path to the TLS private key of server certificate           |
| `address_policies`           | []AddressPolicy | List of allowed addresses to be configured via this api     |

#### Address policy
| Name                   | Type   | Description                                                       |
| ---------------------- | ------ | ----------------------------------------------------------------- |
| `ip_network`           | string | IPv4 or IPv6 network specification that should be allowed         |
| `interface_name_regex` | string | RegExp for interface names that are allowed for the given address |

#### Example
Run `ipam-api --config config.json` with the following configuration as `config.json`:
```json
{
	"port": 44812,
	"client_ca_certificate_path": "client-ca.crt",
	"server_certificate_path": "server.crt",
	"server_key_path": "server.key",
	"address_policies": [
		{
			"ip_network": "fd69:decd:7b66:8220::/64",
			"interface_name_regex": ".*"
		}
	]
}
```

### HTTP-API
An OpenAPI-Specification is available [here](./openapi.yaml). The API is secured by mutual TLS, so a client certificate must be send with the request for authentication.

#### Assign an ip address to a network interface
<table>
	<tr>
		<td><b>Path</b></td>
		<td>/add</td>
	</tr>
	<tr>
		<td><b>Method</b></td>
		<td>POST</td>
	</tr>
	<tr>
		<td><b>Content-Type</b></td>
		<td>application/json</td>
	</tr>
	<tr>
		<td><b>Body</b></td>
		<td><code>{"address": "...", "interface_name": "..."}</code></td>
	</tr>
</table>

A human readable message will be returned on success and on errors.

##### Example
```sh
curl -X POST --cacert server.crt --cert client.crt --key client.key -H "Content-Type: application/json" -d '{"address": "fd69:decd:7b66:8220:5862:69ac:dae1:3785/64", "interface_name": "lo"}' https://localhost:44812/add
```

#### Ensure an ip address is absent on a network interface
<table>
	<tr>
		<td><b>Path</b></td>
		<td>/delete</td>
	</tr>
	<tr>
		<td><b>Method</b></td>
		<td>POST</td>
	</tr>
	<tr>
		<td><b>Content-Type</b></td>
		<td>application/json</td>
	</tr>
	<tr>
		<td><b>Body</b></td>
		<td><code>{"address": "...", "interface_name": "..."}</code></td>
	</tr>
</table>

A human readable message will be returned on success and on errors.

##### Example
```sh
curl -X POST --cacert server.crt --cert client.crt --key client.key -H "Content-Type: application/json" -d '{"address": "fd69:decd:7b66:8220:5862:69ac:dae1:3785/64", "interface_name": "lo"}' https://localhost:44812/delete
```

#### Health check
<table>
	<tr>
		<td><b>Path</b></td>
		<td>/healthz</td>
	</tr>
	<tr>
		<td><b>Method</b></td>
		<td>Get</td>
	</tr>
	<tr>
		<td><b>Body</b></td>
		<td><i>None</i></td>
	</tr>
</table>

A human readable message will be returned on success and on errors.

##### Example
```sh
curl --cacert server.crt https://localhost:44812/healthz
```

## Testing
The tests can be performed by `sudo capsh --caps="cap_net_admin+cap_net_raw+ep" -- -c 'NET_LINK="..." go test ./...'`. The environment variable `NET_LINK` must be set to an existing network interface to which addresses can be assigned. The `NET_ADMIN` capability is required for testing the assignment of an address on a real interface. Extensive logging is enabled to debug any errors.

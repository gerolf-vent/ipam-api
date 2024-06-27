package internal

import (
	"path/filepath"
	"testing"

	"gotest.tools/assert"
)

func TestValidConfiguration(t *testing.T) {
	configFilePath := "../test/config.json"
	config, err := ReadConfiguration(configFilePath)
	assert.NilError(t, err)

	configFilePath, err = filepath.Abs(configFilePath)
	assert.NilError(t, err)

	configDirectoryPath := filepath.Dir(configFilePath)

	assert.Equal(t, config.Port, uint16(44812))
	assert.Equal(t, config.ClientCACertificatePath, AbsPath(configDirectoryPath, "client-ca.crt"))
	assert.Equal(t, config.ServerCertificatePath, AbsPath(configDirectoryPath, "server.crt"))
	assert.Equal(t, config.ServerKeyPath, AbsPath(configDirectoryPath, "server.key"))
	assert.Equal(t, len(config.AddressPolicies), 1)
	assert.Equal(t, config.AddressPolicies[0].InterfaceNameRegex.String(), ".*")
	assert.Equal(t, config.AddressPolicies[0].IPNetwork.String(), "fd69:decd:7b66:8220::/64")
}

func TestMissingParameters(t *testing.T) {
	_, err := ReadConfiguration("../test/config-port-missing.json")
	assert.Error(t, err, "The configuration is missing a port number")

	_, err = ReadConfiguration("../test/config-client-ca-missing.json")
	assert.Error(t, err, "The configuration is missing a path to the client ca certificate")

	_, err = ReadConfiguration("../test/config-server-cert-missing.json")
	assert.Error(t, err, "The configuration is missing a path to the server certificate")

	_, err = ReadConfiguration("../test/config-server-key-missing.json")
	assert.Error(t, err, "The configuration is missing a path to the server key")

	_, err = ReadConfiguration("../test/config-address-policy-missing.json")
	assert.Error(t, err, "The configuration is missing address policies")

	_, err = ReadConfiguration("../test/config-address-policy-empty.json")
	assert.Error(t, err, "The configuration is missing address policies")
}

func TestInvalidAddressPolicyParameters(t *testing.T) {
	_, err := ReadConfiguration("../test/config-address-policy-invalid-address.json")
	assert.Error(t, err, "invalid CIDR address: abcd")

	_, err = ReadConfiguration("../test/config-address-policy-invalid-interface-name-regex.json")
	assert.Error(t, err, "error parsing regexp: missing argument to repetition operator: `*`")
}

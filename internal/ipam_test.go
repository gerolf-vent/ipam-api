package internal

import (
	"os"
	"testing"

	"gotest.tools/assert"
)

func TestExistingInterface(t *testing.T) {
	_, err := LinkByName("lo")
	assert.NilError(t, err)
}

func TestNonExistingInterface(t *testing.T) {
	_, err := LinkByName("abcdef")
	assert.Error(t, err, "Link not found")
}

func TestValidAddresses(t *testing.T) {
	address, err := ParseAddress("127.0.1.1/24")
	assert.NilError(t, err)
	assert.Equal(t, address.String(), "127.0.1.1/24")

	address, err = ParseAddress("127.0.1.0/24")
	assert.NilError(t, err)
	assert.Equal(t, address.String(), "127.0.1.0/24")

	address, err = ParseAddress("fd69:decd:7b66:8220:ae97:d94e:2b27:a6b5/64")
	assert.NilError(t, err)
	assert.Equal(t, address.String(), "fd69:decd:7b66:8220:ae97:d94e:2b27:a6b5/64")

	address, err = ParseAddress("fd69:decd:7b66:8220::/64")
	assert.NilError(t, err)
	assert.Equal(t, address.String(), "fd69:decd:7b66:8220::/64")
}

func TestInvalidAddresses(t *testing.T) {
	_, err := ParseAddress("abc")
	assert.ErrorContains(t, err, "invalid CIDR address:")

	_, err = ParseAddress("127.0.1.0")
	assert.ErrorContains(t, err, "invalid CIDR address:")

	_, err = ParseAddress("127.0.1.0/40")
	assert.ErrorContains(t, err, "invalid CIDR address:")

	_, err = ParseAddress("::1")
	assert.ErrorContains(t, err, "invalid CIDR address:")

	_, err = ParseAddress("::1/200")
	assert.ErrorContains(t, err, "invalid CIDR address:")
}

func TestAddAndDeleteAddress(t *testing.T) {
	assert.Assert(t, os.Getenv("NET_LINK") != "")

	link, err := LinkByName(os.Getenv("NET_LINK"))
	assert.NilError(t, err)

	var address CIDRAddress
	address, err = ParseAddress("fd69:decd:7b66:8220:ae97:d94e:2b27:a6b5/64")
	assert.NilError(t, err)

	var addressExists bool
	addressExists, err = AddressExists(link, address)
	assert.NilError(t, err)
	assert.Equal(t, addressExists, false)

	err = AddAddress(link, address)
	assert.NilError(t, err)

	addressExists, err = AddressExists(link, address)
	assert.NilError(t, err)
	assert.Equal(t, addressExists, true)

	err = DeleteAddress(link, address)
	assert.NilError(t, err)

	addressExists, err = AddressExists(link, address)
	assert.NilError(t, err)
	assert.Equal(t, addressExists, false)
}

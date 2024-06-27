package internal

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"os"
	"testing"

	"gotest.tools/assert"
	"go.uber.org/zap"
)

func TestMain(m *testing.M) {
	zap.ReplaceGlobals(zap.Must(zap.NewDevelopment()))
	defer zap.L().Sync()

	code := m.Run()

	os.Exit(code)
}

func TestNotExisting(t *testing.T) {
	req, err := http.NewRequest("GET", "/invalid", nil)
	if err != nil {
		t.Fatalf("Could not create request: %v", err)
	}

	rr := httptest.NewRecorder()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleRequest(w, r, []AddressPolicy{})
	}))
	defer server.Close()

	server.Config.Handler.ServeHTTP(rr, req)

	assert.Equal(t, rr.Code, http.StatusNotFound)
}

func TestInvalidMethod(t *testing.T) {
	req, err := http.NewRequest("GET", "/add", nil)
	if err != nil {
		t.Fatalf("Could not create request: %v", err)
	}

	rr := httptest.NewRecorder()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleRequest(w, r, []AddressPolicy{})
	}))
	defer server.Close()

	server.Config.Handler.ServeHTTP(rr, req)

	assert.Equal(t, rr.Code, http.StatusMethodNotAllowed)
	assert.Equal(t, rr.Body.String(), "Method Not Allowed\n")
}

func TestInvalidContentType(t *testing.T) {
	requestData := []byte("")

	req, err := http.NewRequest("POST", "/add", bytes.NewBuffer(requestData))
	if err != nil {
		t.Fatalf("Could not create request: %v", err)
	}

	req.Header.Set("Content-Type", "text/html")

	rr := httptest.NewRecorder()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleRequest(w, r, []AddressPolicy{})
	}))
	defer server.Close()

	server.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, rr.Code, http.StatusBadRequest)
	assert.Equal(t, rr.Body.String(), "Invalid content type (expected \"application/json\")\n")
}

func TestNilBody(t *testing.T) {
	req, err := http.NewRequest("POST", "/add", nil)
	if err != nil {
		t.Fatalf("Could not create request: %v", err)
	}

	rr := httptest.NewRecorder()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleRequest(w, r, []AddressPolicy{})
	}))
	defer server.Close()

	server.Config.Handler.ServeHTTP(rr, req)

	assert.Equal(t, rr.Code, http.StatusBadRequest)
	assert.Equal(t, rr.Body.String(), "Request body is empty\n")
}

func TestEmptyBody(t *testing.T) {
	requestData := []byte("{}")

	req, err := http.NewRequest("POST", "/add", bytes.NewBuffer(requestData))
	if err != nil {
		t.Fatalf("Could not create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleRequest(w, r, []AddressPolicy{})
	}))
	defer server.Close()

	server.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, rr.Code, http.StatusBadRequest)
	assert.Equal(t, rr.Body.String(), "Address (\"address\") is missing in request\n")
}

func TestAddAddressWithPolicyMismatch(t *testing.T) {
	assert.Assert(t, os.Getenv("NET_LINK") != "")

	requestData := []byte("{\"address\":\"fd69:decd:7b66:8220:b37a:817a:cabd:35c0/64\", \"interface_name\":\"" + os.Getenv("NET_LINK") + "\"}")

	req, err := http.NewRequest("POST", "/add", bytes.NewBuffer(requestData))
	if err != nil {
		t.Fatalf("Could not create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_, policyIPNetwork, err := net.ParseCIDR("fd69:decd:7b66:8220::/64")
	assert.NilError(t, err)

	policyInterfaceNameRegexp, err := regexp.Compile("^lo$")
	assert.NilError(t, err)

	policies := []AddressPolicy{
		AddressPolicy{ IPNetwork{*policyIPNetwork}, Regexp{*policyInterfaceNameRegexp} },
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleRequest(w, r, policies)
	}))
	defer server.Close()

	server.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, rr.Code, http.StatusForbidden)
	assert.Equal(t, rr.Body.String(), "Rejected cidr address for interface, because no matching policy was found\n")
}

func TestAddAndDeleteAddressWithPolicyMatch(t *testing.T) {
	assert.Assert(t, os.Getenv("NET_LINK") != "")

	_, err := LinkByName(os.Getenv("NET_LINK"))
	assert.NilError(t, err)

	requestData := []byte("{\"address\":\"fd69:decd:7b66:8220:b37a:817a:cabd:35c0/64\", \"interface_name\":\"" + os.Getenv("NET_LINK") + "\"}")

	req, err := http.NewRequest("POST", "/add", bytes.NewBuffer(requestData))
	if err != nil {
		t.Fatalf("Could not create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_, policyIPNetwork, err := net.ParseCIDR("fd69:decd:7b66:8220::/64")
	assert.NilError(t, err)

	policyInterfaceNameRegexp, err := regexp.Compile(".*")
	assert.NilError(t, err)

	policies := []AddressPolicy{
		AddressPolicy{ IPNetwork{*policyIPNetwork}, Regexp{*policyInterfaceNameRegexp} },
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleRequest(w, r, policies)
	}))
	defer server.Close()

	server.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, rr.Code, http.StatusOK)
	assert.Equal(t, rr.Body.String(), "Successfully added address to interface\n")

	req, err = http.NewRequest("POST", "/delete", bytes.NewBuffer(requestData))
	if err != nil {
		t.Fatalf("Could not create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	rr = httptest.NewRecorder()

	server.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, rr.Code, http.StatusOK)
	assert.Equal(t, rr.Body.String(), "Successfully deleted address from interface\n")
}

func TestAddAddressToNonExistingInterfaceWithPolicyMatch(t *testing.T) {
	requestData := []byte("{\"address\":\"fd69:decd:7b66:8220:b37a:817a:cabd:35c0/64\", \"interface_name\":\"abcd\"}")

	req, err := http.NewRequest("POST", "/add", bytes.NewBuffer(requestData))
	if err != nil {
		t.Fatalf("Could not create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_, policyIPNetwork, err := net.ParseCIDR("fd69:decd:7b66:8220::/64")
	assert.NilError(t, err)

	policyInterfaceNameRegexp, err := regexp.Compile(".*")
	assert.NilError(t, err)

	policies := []AddressPolicy{
		AddressPolicy{ IPNetwork{*policyIPNetwork}, Regexp{*policyInterfaceNameRegexp} },
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleRequest(w, r, policies)
	}))
	defer server.Close()

	server.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, rr.Code, http.StatusInternalServerError)
	assert.Equal(t, rr.Body.String(), "Failed to retreive interface: Link not found\n")
}

func TestDeleteAddressToNonExistingInterfaceWithPolicyMatch(t *testing.T) {
	requestData := []byte("{\"address\":\"fd69:decd:7b66:8220:b37a:817a:cabd:35c0/64\", \"interface_name\":\"abcd\"}")

	req, err := http.NewRequest("POST", "/delete", bytes.NewBuffer(requestData))
	if err != nil {
		t.Fatalf("Could not create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	_, policyIPNetwork, err := net.ParseCIDR("fd69:decd:7b66:8220::/64")
	assert.NilError(t, err)

	policyInterfaceNameRegexp, err := regexp.Compile(".*")
	assert.NilError(t, err)

	policies := []AddressPolicy{
		AddressPolicy{ IPNetwork{*policyIPNetwork}, Regexp{*policyInterfaceNameRegexp} },
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleRequest(w, r, policies)
	}))
	defer server.Close()

	server.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, rr.Code, http.StatusInternalServerError)
	assert.Equal(t, rr.Body.String(), "Failed to retreive interface: Link not found\n")
}

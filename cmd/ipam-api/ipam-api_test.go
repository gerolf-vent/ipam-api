package main

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"io/ioutil"
	"time"
	"os"
	"testing"

	"gotest.tools/assert"
	"go.uber.org/zap"
	i "github.com/gerolf-vent/ipam-api/v2/internal"
)

func TestMain(m *testing.M) {
	zap.ReplaceGlobals(zap.Must(zap.NewDevelopment()))
	defer zap.L().Sync()

	go func() {
		i.RunServer("../../test/config.json")
	}()

	time.Sleep(2 * time.Second)

	code := m.Run()

	os.Exit(code)
}

func TestUnauthorizedRequest(t *testing.T) {
	serverCA, err := ioutil.ReadFile("../../test/server.crt")
	if err != nil {
		t.Fatalf("Failed to read server CA certificate: %v", err)
	}
	serverCAPool := x509.NewCertPool()
	serverCAPool.AppendCertsFromPEM(serverCA)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            serverCAPool,
			},
		},
	}

	resp, err := client.Get("https://localhost:44812/")
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	assert.Equal(t, resp.StatusCode, http.StatusUnauthorized)
	assert.Equal(t, string(body), "Unauthorized\n")
}

func TestInvalidAuthorizationRequest(t *testing.T) {
	serverCA, err := ioutil.ReadFile("../../test/server.crt")
	if err != nil {
		t.Fatalf("Failed to read server CA certificate: %v", err)
	}
	serverCAPool := x509.NewCertPool()
	serverCAPool.AppendCertsFromPEM(serverCA)

	clientCert, err := tls.LoadX509KeyPair("../../test/server.crt", "../../test/server.key")
	if err != nil {
		t.Fatalf("Failed to load client certificate and key: %v", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{clientCert},
				RootCAs:            serverCAPool,
			},
		},
	}

	resp, err := client.Get("https://localhost:44812/")
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	assert.Equal(t, resp.StatusCode, http.StatusForbidden)
	assert.Equal(t, string(body), "Access denied\n")
}

func TestValidAuthorizationRequest(t *testing.T) {
	serverCA, err := ioutil.ReadFile("../../test/server.crt")
	if err != nil {
		t.Fatalf("Failed to read server CA certificate: %v", err)
	}
	serverCAPool := x509.NewCertPool()
	serverCAPool.AppendCertsFromPEM(serverCA)

	clientCert, err := tls.LoadX509KeyPair("../../test/client.crt", "../../test/client.key")
	if err != nil {
		t.Fatalf("Failed to load client certificate and key: %v", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{clientCert},
				RootCAs:            serverCAPool,
			},
		},
	}

	resp, err := client.Get("https://localhost:44812/")
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	assert.Equal(t, resp.StatusCode, http.StatusNotFound)
	assert.Equal(t, string(body), "Path not found\n")
}

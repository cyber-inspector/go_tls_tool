package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
)

var version = "1.0.0"
var tlsToolConfig *TLSToolConfig

type TLSToolConfig struct {
	Mode                  string `json:"mode"`
	Address               string `json:"address"`
	Servername            string `json:"servername"`
	CertDir               string `json:"cert_dir"`
	Port                  string `json:"port"`
	InsecureSkipVerify    bool   `json:"insecure_skip_verify"`
	NoUseTLSIntermediates bool   `json:"no_use_tls_intermediates"`
	TLSMinVersion         string `json:"tls_min_version"`
	TLSMaxVersion         string `json:"tls_max_version"`
	printVersion          bool
	NoDumpResult          bool `json:"no_dump_result"`
}

type TLSToolResult struct {
	RunDate string         `json:"run_date"`
	Config  *TLSToolConfig `json:"config"`
	Result  interface{}    `json:"result"`
}

type ChainBuilderResult struct {
	PeerCertificates []*ChainLink   `json:"peer_certificates"`
	DefaultChains    [][]*ChainLink `json:"default_chains"`
	CustomPoolChains [][]*ChainLink `json:"custom_pool_chains"`
}

type TLSVersionResult struct {
	ServerName       string
	Address          string
	Version          string
	CipherSuite      string
	PeerCertificates []*ChainLink `json:"peer_certificates"`
}

var rootCertPool *x509.CertPool
var intermediateCertPool *x509.CertPool

func main() {
	fmt.Println("Go TLS Tool Version:", version, "OS:", runtime.GOOS, "Arch:", runtime.GOARCH)
	tlsToolConfig = ParseCommandLineArgs()

	if tlsToolConfig.printVersion == true {
		os.Exit(0)
	} else {
		if tlsToolConfig.Mode == "" {
			log.Fatal("Mode (-m/--mode) is required.")
		} else if tlsToolConfig.Address == "" {
			log.Fatal("Address (-a/--address) is required.")
		}
	}

	var result interface{}

	if tlsToolConfig.Mode == "chains" {
		result = modeGetChains()
	} else if tlsToolConfig.Mode == "tlsVersion" {
		result = modeGetTLS()
	} else {
		log.Fatal("Unknown mode: '" + tlsToolConfig.Mode + "'. Available values: chains, tlsVersion")
	}

	if tlsToolConfig.NoDumpResult == false {
		dumpResultToFIle(result)
	}
	os.Exit(0)
}

func modeGetChains() interface{} {
	// Load certs root/intermediate from
	loadCerts(tlsToolConfig.CertDir)

	r, rErr := doTLS(
		tlsToolConfig.Address,
		tlsToolConfig.Port,
		0,
		0,
	)

	if rErr != nil {
		log.Fatal("An error occurred trying to establish a tls connection:", rErr.Error())
	}

	if r == nil {
		log.Fatal("Failed to make a TLS connection for address: " + tlsToolConfig.Address + ". Please check the address and try again.")
	}

	cbr := ChainBuilderResult{}
	processCerts(&cbr, r)
	return &cbr
}

func modeGetTLS() interface{} {
	r, rErr := doTLS(
		tlsToolConfig.Address,
		tlsToolConfig.Port,
		0,
		0,
	)

	if rErr != nil {
		log.Fatal("An error occurred trying to establish a tls connection:", rErr.Error())
	}

	if r == nil {
		log.Fatal("Failed to make a TLS connection for address: " + tlsToolConfig.Address + ". Please check the address and try again.")
	}

	tlr := TLSVersionResult{
		ServerName:       r.ServerName,
		Address:          r.Address,
		CipherSuite:      tls.CipherSuiteName(r.CipherSuite),
		PeerCertificates: nil,
	}

	for tlsVersionString, tlsVersionUint := range tlsVersionsMap {
		if tlsVersionUint == r.Version {
			tlr.Version = tlsVersionString
			break
		}
	}

	log.Println("TLS Connection Details:")
	fmt.Println("TLSVersion:", tlr.Version)
	fmt.Println("CipherSuite:", tlr.CipherSuite)
	fmt.Println()
	fmt.Println("Certificate(s) received from the TLS connection:")
	for i, c := range r.PeerCertificates {
		peerCertConverted := CreateChainLink(c)
		tlr.PeerCertificates = append(tlr.PeerCertificates, peerCertConverted)
		fmt.Println("["+strconv.Itoa(i)+"]", GetCertSummaryString(peerCertConverted))
	}
	return tlr
}

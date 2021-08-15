package main

import (
	"crypto/x509"
	"fmt"
	"log"
	"os"
)

var version = "1.0.0"
var config *TLSToolConfig

type TLSToolConfig struct {
	Mode                  string `json:"mode"`
	Address               string `json:"address"`
	Servername            string `json:"servername"`
	CertDir               string `json:"cert_dir"`
	Port                  string `json:"port"`
	NoUseTLSIntermediates int    `json:"no_use_tls_intermediates"`
	printVersion          bool
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

var rootCertPool *x509.CertPool
var intermediateCertPool *x509.CertPool

func main() {
	config = ParseCommandLineArgs()

	if config.printVersion == true {
		fmt.Println("Go TLS Tool Version: " + version)
		os.Exit(0)
	} else {
		if config.Mode == "" {
			log.Fatal("Mode (-m/--mode) is required.")
		} else if config.Address == "" {
			log.Fatal("Address (-a/--address) is required.")
		}
	}

	var result interface{}

	if config.Mode == "chains" {
		result = modeGetChains()
	} else {
		log.Fatal("Unknown mode: '" + config.Mode + "'.")
	}

	dumpResultToFIle(result)
	os.Exit(0)
}

func modeGetChains() interface{} {
	// Load certs root/intermediate from
	loadCerts(config.CertDir)

	r, rErr := getChains(
		config.Address,
		config.Port,
		config.Servername,
		false,
		0,
		0,
	)

	if rErr != nil {
		log.Fatal(rErr)
	}

	if r == nil {
		log.Fatal("Failed to make a TLS connection for address: " + config.Address + ". Please check the address and try again.")
	}

	cbr := ChainBuilderResult{}
	processCerts(&cbr, r)
	return &cbr
}

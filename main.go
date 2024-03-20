package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"time"
)

var version = "1.0.4"
var tlsToolConfig *TLSToolConfig

type TLSToolConfig struct {
	Mode                  string `json:"mode"`
	Address               string `json:"address"`
	Servername            string `json:"servername"`
	CertDir               string `json:"cert_dir"`
	Port                  int    `json:"port"`
	InsecureSkipVerify    bool   `json:"insecure_skip_verify"`
	NoUseTLSIntermediates bool   `json:"no_use_tls_intermediates"`
	TLSVersion            string `json:"tls_version"`
	TLSMinVersion         string `json:"tls_min_version"`
	TLSMaxVersion         string `json:"tls_max_version"`
	printVersion          bool
	dumpResult            bool
	printCerts            bool
	printCertFields       string
	setEvalTime           string
}

type TLSToolResult struct {
	RunDate string         `json:"run_date"`
	Config  *TLSToolConfig `json:"config"`
	Result  interface{}    `json:"result"`
}

type ChainBuilderResult struct {
	ServerName       string
	Address          string
	Version          string
	CipherSuite      string
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
	log.Println("Go TLS Tool Version:"+version, "OS:"+runtime.GOOS, "Arch:"+runtime.GOARCH)
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

	if tlsToolConfig.printCertFields != "" && tlsToolConfig.printCerts == false {
		log.Println("Warning: -F|--print-cert-fields has been set but -t/--print-certs has not.")
	}

	var result interface{}

	var evalTime time.Time
	if tlsToolConfig.setEvalTime == "" {
		evalTime = time.Now()
	} else {
		var err error
		evalTime, err = time.Parse(time.RFC3339, tlsToolConfig.setEvalTime)
		if err != nil {
			fmt.Println(err.Error())
		}
	}
	fmt.Println("Using the following time for cert validity: " + evalTime.String())

	if tlsToolConfig.Mode == "chains" {
		result = modeGetChains(evalTime)
	} else if tlsToolConfig.Mode == "tlsVersion" {
		result = modeGetTLS(evalTime)
	} else {
		log.Fatal("Unknown mode: '" + tlsToolConfig.Mode + "'. Available values: chains, tlsVersion")
	}

	if tlsToolConfig.dumpResult == true {
		dumpResultToFIle(result)
	}

	os.Exit(0)
}

func modeGetChains(evalTime time.Time) interface{} {
	// Load certs root/intermediate from
	loadCerts(tlsToolConfig.CertDir)

	r, rErr := doTLS(
		tlsToolConfig.Address,
		strconv.Itoa(tlsToolConfig.Port),
		0,
		0,
		evalTime,
	)

	if rErr != nil {
		log.Fatal("An error occurred trying to establish a TLS connection:", rErr.Error())
	}

	if r == nil {
		log.Fatal("Failed to make a TLS connection for address: " + tlsToolConfig.Address + ". Please check the address and try again.")
	}

	cbr := ChainBuilderResult{
		ServerName:  r.ServerName,
		Address:     r.Address,
		CipherSuite: tls.CipherSuiteName(r.CipherSuite),
	}

	for tlsVersionString, tlsVersionUint := range tlsVersionsMap {
		if tlsVersionUint == r.Version {
			cbr.Version = tlsVersionString
			break
		}
	}

	fmt.Println("TLS Connection Details")
	fmt.Println("----------------------")
	fmt.Println("TLSVersion:", cbr.Version)
	fmt.Println("CipherSuite:", cbr.CipherSuite)
	fmt.Println()
	processCerts(&cbr, r)
	return &cbr
}

func modeGetTLS(evalTime time.Time) interface{} {
	r, rErr := doTLS(
		tlsToolConfig.Address,
		strconv.Itoa(tlsToolConfig.Port),
		0,
		0,
		evalTime,
	)

	if rErr != nil {
		log.Fatal("An error occurred trying to establish a tls connection:", rErr.Error())
	}

	if r == nil {
		log.Fatal("Failed to make a TLS connection for address: " + tlsToolConfig.Address + ". Please check the address and try again.")
	}

	tlr := TLSVersionResult{
		ServerName:  r.ServerName,
		Address:     r.Address,
		CipherSuite: tls.CipherSuiteName(r.CipherSuite),
	}

	for tlsVersionString, tlsVersionUint := range tlsVersionsMap {
		if tlsVersionUint == r.Version {
			tlr.Version = tlsVersionString
			break
		}
	}

	fmt.Println("TLS Connection Details")
	fmt.Println("----------------------")
	fmt.Println("TLSVersion:", tlr.Version)
	fmt.Println("CipherSuite:", tlr.CipherSuite)
	fmt.Println()
	if tlsToolConfig.printCerts == true {
		fmt.Println("Certificate(s) received from the TLS handshake")
		fmt.Println("----------------------------------------------")
	}
	for i, c := range r.PeerCertificates {
		peerCertConverted := CreateChainLink(c)
		tlr.PeerCertificates = append(tlr.PeerCertificates, peerCertConverted)
		if tlsToolConfig.printCerts == true {
			fmt.Println("Certificate " + strconv.Itoa(i+1))
			fmt.Println(GetCertSummaryString(peerCertConverted))
			fmt.Println()
		}
	}
	return tlr
}

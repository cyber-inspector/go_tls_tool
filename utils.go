package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/akamensky/argparse"
	"hash"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func intListToString(intList []int) string {
	s := ""
	for _, i := range intList {
		s += strconv.Itoa(i) + "."
	}
	s = strings.TrimSuffix(s, ".")
	return s
}

func BytesToHexWithSeparator(b []byte, separator rune) string {
	bHex := hex.EncodeToString(b)
	var bHexRune []rune
	for i, c := range bHex {
		if i%2 == 0 && i > 0 {
			bHexRune = append(bHexRune, separator)
		}
		bHexRune = append(bHexRune, c)
	}
	return strings.ToUpper(string(bHexRune))
}

func GetCertFingerprint(hashAlgo string, b []byte) string {
	var h hash.Hash
	if hashAlgo == "SHA256" {
		h = sha256.New()
	} else if hashAlgo == "SHA1" {
		h = sha1.New()
	} else if hashAlgo == "MD5" {
		h = md5.New()
	}

	if h == nil {
		return ""
	}
	h.Write(b)
	bs := h.Sum(nil)
	return BytesToHexWithSeparator(bs, ':')
}

func HasBit(n int, pos int) bool {
	val := n & pos
	return val > 0
}

func ParseCommandLineArgs() *TLSToolConfig {
	parser := argparse.NewParser("Chain Builder", "Build certificate chains for a given domain")
	mode := parser.String(
		"m",
		"mode",
		&argparse.Options{
			Required: false,
			Help:     "Which mode to use, Available values: chains, tlsVersion",
		})
	printVersion := parser.Flag(
		"V",
		"version",
		&argparse.Options{
			Required: false,
			Help:     "Display the version of this application.",
		})
	address := parser.String(
		"a",
		"address",
		&argparse.Options{
			Required: false,
			Help: "Address for opening tcp connection e.g www.example.com. An ip address can also be used." +
				"Servername (-s/--servername) can be used to specify the servername used for SNI.",
		})
	port := parser.Int(
		"p",
		"port",
		&argparse.Options{
			Required: false,
			Help:     "Port to use for the tcp connection. Default: 443",
		})
	servername := parser.String(
		"s",
		"servername",
		&argparse.Options{
			Required: false,
			Help: "Name used for TLS SNI extension and certificate verification. If not specified the value for" +
				" (-a/--address) will be used.",
		})
	certDir := parser.String(
		"d",
		"cert-dir",
		&argparse.Options{
			Required: false,
			Help: "Path to the directory that contains the folders 'root' and 'intermediate' to load certificates" +
				" for extra/specific chain building. NOTE: only used for mode: chains",
		})
	noUseTLSIntermediates := parser.Flag(
		"n",
		"no-use-tls-intermediates",
		&argparse.Options{
			Required: false,
			Help: "Do not try and use the intermediate(s) provided by the TLS handshake for the construction" +
				" of default tls chains. NOTE: only used for mode: chains",
		})
	insecureSkipVerify := parser.Flag(
		"i",
		"insecure-skip-verify",
		&argparse.Options{
			Required: false,
			Help: "Set tls.Config.InsecureSkipVerify to true i.e. accept any certificate" +
				" provided by the remote host.",
		})
	tlsMinVersion := parser.String(
		"u",
		"tls-min-version",
		&argparse.Options{
			Required: false,
			Help:     "Minimum TLS version to use in handshake. Available values: " + getSupportedTLSVersionsString(),
		})
	tlsMaxVersion := parser.String(
		"x",
		"tls-max-version",
		&argparse.Options{
			Required: false,
			Help:     "Maximum TLS version to use in handshake. Available values: " + getSupportedTLSVersionsString(),
		})
	tlsVersion := parser.String(
		"T",
		"tls-version",
		&argparse.Options{
			Required: false,
			Help:     "Sole TLS version to use in handshake. Available values: " + getSupportedTLSVersionsString(),
		})
	dumpResult := parser.Flag(
		"o",
		"dump-result",
		&argparse.Options{
			Required: false,
			Help:     "Dump the output to a file in the format: <mode>-<address>-<servername>-<epochTimeSeconds<.json",
		})
	printCerts := parser.Flag(
		"t",
		"print-certs",
		&argparse.Options{
			Required: false,
			Help:     "Print the certificates from the TLS handshake to the console.",
		})
	printCertFields := parser.String(
		"F",
		"print-cert-fields",
		&argparse.Options{
			Required: false,
			Help: "Fields from the x509 certificate to print to the console." +
				" This applies to -t/-print-certs and chains mode.",
		})
	setEvalTime := parser.String(
		"e",
		"set-eval-time",
		&argparse.Options{
			Required: false,
			Help:     "Set the 'now' time for the certificate(s) to be evaluated with.",
		})
	err := parser.Parse(os.Args)
	if err != nil {
		// In case of error print error and print usage
		// This can also be done by passing -h or --help flags
		fmt.Printf("ERROR: error parsing args %s\n", err.Error())
		os.Exit(1)
	}
	if *port == 0 {
		*port = 443
	} else if *port < 0 {
		log.Fatal("Port must between 1 and 65535")
	} else if *port > 65535 {
		log.Fatal("Port must between 1 and 65535")
	}
	conf := TLSToolConfig{
		Mode:                  *mode,
		Address:               *address,
		Servername:            *servername,
		CertDir:               *certDir,
		Port:                  *port,
		InsecureSkipVerify:    *insecureSkipVerify,
		NoUseTLSIntermediates: *noUseTLSIntermediates,
		TLSVersion:            *tlsVersion,
		printVersion:          *printVersion,
		TLSMinVersion:         *tlsMinVersion,
		TLSMaxVersion:         *tlsMaxVersion,
		dumpResult:            *dumpResult,
		printCerts:            *printCerts,
		printCertFields:       *printCertFields,
		setEvalTime:           *setEvalTime,
	}
	return &conf
}

func loadCerts(certDir string) {
	if certDir != "" {
		rootCertDir := filepath.Join(certDir, "root")
		rootPemCertPool, rootPemCertListErr := CreateCertPoolFromDir(rootCertDir, "root")
		if rootPemCertListErr != nil {
			fmt.Println("Failed to load root certificates from", rootCertDir, "due to",
				rootPemCertListErr.Error())
			//os.Exit(1)
		}
		rootCertPool = rootPemCertPool

		intermediateCertDir := filepath.Join(certDir, "intermediate")
		intermediatePemCertPool, intermediatePemCertListErr := CreateCertPoolFromDir(
			intermediateCertDir, "intermediate")
		if intermediatePemCertListErr != nil {
			fmt.Println("Failed to load root certificates from", intermediateCertDir, "due to",
				intermediatePemCertListErr.Error())
			//os.Exit(1)
		}
		intermediateCertPool = intermediatePemCertPool
	} else {
		fmt.Println("No path specified for -d/--cert-dir. No custom chains will be attempted to be built." +
			" Default chains will still be attempted to be built.")
		fmt.Println()
	}
}

func structToJsonStr(obj interface{}) ([]byte, error) {
	objMarshalled, objMarshalledErr := json.MarshalIndent(obj, "", "  ")
	if objMarshalledErr != nil {
		return nil, objMarshalledErr
	} else {
		return objMarshalled, nil
	}
}

func dumpResultToFIle(result interface{}) {
	ttr := TLSToolResult{
		RunDate: time.Now().UTC().Format("2006-01-02T15:04:05 -0700"),
		Config:  tlsToolConfig,
		Result:  result,
	}
	stj, stjErr := structToJsonStr(ttr)
	if stjErr != nil {
		log.Fatal("Unable to json marshal the output object due to " + stjErr.Error())
	}

	outputFilename := tlsToolConfig.Mode + "_" + tlsToolConfig.Address
	if tlsToolConfig.Servername != "" {
		outputFilename += "_" + tlsToolConfig.Servername
	} else {
		outputFilename += "_" + tlsToolConfig.Address
	}
	outputFilename += "_"
	outputFilename += strconv.FormatInt(time.Now().Unix(), 10)
	outputFilename += ".json"
	outputFilename, _ = filepath.Abs(outputFilename)
	file, fileErr := os.Create(outputFilename)
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Fatal("Unable to close the file " + outputFilename + " due to " + err.Error())
		}
	}(file)
	if fileErr != nil {
		log.Fatal("Unable to create the file: " + outputFilename + " due to " + fileErr.Error())
	}
	writer := bufio.NewWriter(file)
	_, writeErr := writer.Write(stj)
	if writeErr != nil {
		log.Fatal("There was an error writing to the file: " + outputFilename + " due to " + fileErr.Error())
	}
	err := writer.Flush()
	if err != nil {
		log.Fatal("There was an error flushing the file: " + outputFilename + " due to " + fileErr.Error())
	}
	fmt.Println()
	fmt.Println("More detailed information has been dumped to the file: " + outputFilename)
}

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Taken from x509.go:601
var (
	oidExtKeyUsageAny                            = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	oidExtKeyUsageServerAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidExtKeyUsageClientAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidExtKeyUsageCodeSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	oidExtKeyUsageEmailProtection                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	oidExtKeyUsageIPSECEndSystem                 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
	oidExtKeyUsageIPSECTunnel                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
	oidExtKeyUsageIPSECUser                      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
	oidExtKeyUsageTimeStamping                   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidExtKeyUsageOCSPSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
	oidExtKeyUsageMicrosoftServerGatedCrypto     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}
	oidExtKeyUsageNetscapeServerGatedCrypto      = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}
	oidExtKeyUsageMicrosoftCommercialCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 22}
	oidExtKeyUsageMicrosoftKernelCodeSigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}
)

var extraKeyUsageToStringMap = map[x509.ExtKeyUsage]*ExtraKeyUsage{
	x509.ExtKeyUsageAny:                            {"Any", intListToString(oidExtKeyUsageAny)},
	x509.ExtKeyUsageServerAuth:                     {"ServerAuth", intListToString(oidExtKeyUsageServerAuth)},
	x509.ExtKeyUsageClientAuth:                     {"ClientAuth", intListToString(oidExtKeyUsageClientAuth)},
	x509.ExtKeyUsageCodeSigning:                    {"CodeSigning", intListToString(oidExtKeyUsageCodeSigning)},
	x509.ExtKeyUsageEmailProtection:                {"EmailProtection", intListToString(oidExtKeyUsageEmailProtection)},
	x509.ExtKeyUsageIPSECEndSystem:                 {"IPSECEndSystem", intListToString(oidExtKeyUsageIPSECEndSystem)},
	x509.ExtKeyUsageIPSECTunnel:                    {"IPSECTunnel", intListToString(oidExtKeyUsageIPSECTunnel)},
	x509.ExtKeyUsageIPSECUser:                      {"IPSECUser", intListToString(oidExtKeyUsageIPSECUser)},
	x509.ExtKeyUsageTimeStamping:                   {"TimeStamping", intListToString(oidExtKeyUsageTimeStamping)},
	x509.ExtKeyUsageOCSPSigning:                    {"OCSPSigning", intListToString(oidExtKeyUsageOCSPSigning)},
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     {"MicrosoftServerGatedCrypto", intListToString(oidExtKeyUsageMicrosoftServerGatedCrypto)},
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      {"NetscapeServerGatedCrypto", intListToString(oidExtKeyUsageNetscapeServerGatedCrypto)},
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: {"MicrosoftCommercialCodeSigning", intListToString(oidExtKeyUsageMicrosoftCommercialCodeSigning)},
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     {"MicrosoftKernelCodeSigning", intListToString(oidExtKeyUsageMicrosoftKernelCodeSigning)},
}

var keyUsageToStringMap = map[x509.KeyUsage]*ExtraKeyUsage{
	x509.KeyUsageDigitalSignature:  {"DigitalSignature", "2.5.29.15"},
	x509.KeyUsageContentCommitment: {"ContentCommitment", "2.5.29.15"},
	x509.KeyUsageKeyEncipherment:   {"KeyEncipherment", "2.5.29.15"},
	x509.KeyUsageDataEncipherment:  {"DataEncipherment", "2.5.29.15"},
	x509.KeyUsageKeyAgreement:      {"KeyAgreement", "2.5.29.15"},
	x509.KeyUsageCertSign:          {"CertSign", "2.5.29.15"},
	x509.KeyUsageCRLSign:           {"CRLSign", "2.5.29.15"},
	x509.KeyUsageEncipherOnly:      {"EncipherOnly", "2.5.29.15"},
	x509.KeyUsageDecipherOnly:      {"DecipherOnly", "2.5.29.15"},
}

var keyUsageList = []x509.KeyUsage{
	x509.KeyUsageDigitalSignature,
	x509.KeyUsageContentCommitment,
	x509.KeyUsageKeyEncipherment,
	x509.KeyUsageDataEncipherment,
	x509.KeyUsageKeyAgreement,
	x509.KeyUsageCertSign,
	x509.KeyUsageCRLSign,
	x509.KeyUsageEncipherOnly,
	x509.KeyUsageDecipherOnly,
}

var tlsVersionsMap = map[string]uint16{
	"TLS10": tls.VersionTLS10,
	"TLS11": tls.VersionTLS11,
	"TLS12": tls.VersionTLS12,
	"TLS13": tls.VersionTLS13,
}

var certFieldsMap = map[string]bool{
	"subject":        true,
	"issuer":         true,
	"ski":            true,
	"aki":            true,
	"notAfter":       true,
	"notBefore":      true,
	"certMD5":        true,
	"certSHA1":       true,
	"certSHA256":     true,
	"dnsNames":       true,
	"emailAddresses": true,
	"uris":           true,
	"keyUsage":       true,
	"extraKeyUsage":  true,
	"certPEM":        true,
}

// Copied from http.transport.go
type tlsHandshakeTimeoutError struct{}

func (tlsHandshakeTimeoutError) Timeout() bool   { return true }
func (tlsHandshakeTimeoutError) Temporary() bool { return true }
func (tlsHandshakeTimeoutError) Error() string   { return "TLS handshake timeout" }

type TLSInfo struct {
	ServerName         string
	Address            string
	Version            uint16
	CipherSuite        uint16
	NegotiatedProtocol string
	PeerCertificates   []*x509.Certificate
	OCSPResponse       []byte
}

type ExtraKeyUsage struct {
	Name string `json:"name"`
	Oid  string `json:"oid"`
}

type ChainLink struct {
	Subject                string           `json:"subject"`
	Issuer                 string           `json:"issuer"`
	DNSNames               []string         `json:"dns_names"`
	EmailAddresses         []string         `json:"email_addresses"`
	IPAddresses            []string         `json:"ip_addresses"`
	URIs                   []string         `json:"uris"`
	NotBefore              string           `json:"not_before"`
	NotBeforeEpoch         int64            `json:"not_before_epoch"`
	NotAfter               string           `json:"not_after"`
	NotAfterEpoch          int64            `json:"not_after_epoch"`
	SubjectKeyIdentifier   string           `json:"subject_key_identifier"`
	AuthorityKeyIdentifier string           `json:"authority_key_identifier"`
	ExtraKeyUsage          []*ExtraKeyUsage `json:"extra_key_usage"`
	KeyUsage               []*ExtraKeyUsage `json:"key_usage"`
	CertFingerprints       CertFingerprints `json:"cert_fingerprints"`
	CertPem                string           `json:"cert_pem"`
}

type CertFingerprints struct {
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
}

func GetExtKeyUsageDetail(e x509.ExtKeyUsage) *ExtraKeyUsage {
	if _, ok := extraKeyUsageToStringMap[e]; ok {
		return extraKeyUsageToStringMap[e]
	}
	return nil
}

func GetKeyUsageDetail(e x509.KeyUsage) *ExtraKeyUsage {
	if _, ok := keyUsageToStringMap[e]; ok {
		return keyUsageToStringMap[e]
	}
	return nil
}

// doTLS establishes a TLS connection and returns some metadata about the connection should a successful
// tls connection be made.
// address is the ip address or domain used to obtain the ip address for the target of the TLS connection
// servername is the SNI value
// insecureSkipVerify when true will disable certificate verification (default is false)
// tcpDialTimeout how long to wait to create a tcp connection before aborting
// tlsHandshakeTimeout how long to wait to create a tls connection before aborting
func doTLS(address string, port string, tcpDialTimeout time.Duration, tlsHandshakeTimeout time.Duration, evalTime time.Time,
) (*TLSInfo, error) {
	var tlsInfo TLSInfo

	cfg := constructTLSConfig(evalTime)

	// Create a TCP connection to the target address
	dailAddress := address
	if port != "" {
		dailAddress += ":" + port
	} else {
		dailAddress += ":443"
	}
	conn, err := net.DialTimeout("tcp", dailAddress, tcpDialTimeout)
	if err != nil {
		return nil, err
	}
	tlsClient := tls.Client(conn, cfg)

	// Taken from http.transport.go:persistConn.addTLS
	errChannel := make(chan error, 2)
	var timer *time.Timer // for canceling TLS handshake

	// Create a timer to allow the tls handshake to timeout if tlsHandshakeTimeout is greater than 0
	if tlsHandshakeTimeout != 0 {
		timer = time.AfterFunc(tlsHandshakeTimeout, func() {
			errChannel <- tlsHandshakeTimeoutError{}
		})
	}

	// Use the timer to enforce a timeout if tlsHandshakeTimeout is greater than 0
	go func() {
		err := tlsClient.Handshake()
		if timer != nil {
			timer.Stop()
		}
		errChannel <- err
	}()

	// A TLS error occurred
	if tlsHandshakeErr := <-errChannel; tlsHandshakeErr != nil {
		return nil, tlsHandshakeErr
	}
	defer func(tlsClient *tls.Conn) {
		err := tlsClient.Close()
		if err != nil {
			log.Println("Error closing TLS connection for address " + address + ": " + err.Error())
		}
	}(tlsClient)
	connState := tlsClient.ConnectionState()

	// Populate a TLSInfo and return it
	tlsInfo = TLSInfo{
		ServerName:         cfg.ServerName,
		Address:            address,
		Version:            connState.Version,
		CipherSuite:        connState.CipherSuite,
		NegotiatedProtocol: connState.NegotiatedProtocol,
		PeerCertificates:   connState.PeerCertificates,
		OCSPResponse:       connState.OCSPResponse,
	}
	return &tlsInfo, nil
}

func processCerts(cbr *ChainBuilderResult, r *TLSInfo) {
	if len(r.PeerCertificates) == 0 {
		log.Fatal("No certificates provided on the TLS handshake for address: " + tlsToolConfig.Address + ".")
	}

	if tlsToolConfig.printCerts == true {
		fmt.Println("Certificate(s) received from the TLS handshake")
		fmt.Println("----------------------------------------------")
	}

	for i, c := range r.PeerCertificates {
		peerCertConverted := CreateChainLink(c)
		if tlsToolConfig.printCerts == true {
			fmt.Println("Certificate " + strconv.Itoa(i+1))
			fmt.Println(GetCertSummaryString(peerCertConverted))
			fmt.Println()
		}
	}
	fmt.Println()

	var dnsName string
	if tlsToolConfig.Servername != "" {
		dnsName = tlsToolConfig.Servername
	} else {
		dnsName = tlsToolConfig.Address
	}
	leafCert := r.PeerCertificates[0]

	localIntermediatePool := x509.NewCertPool()

	for i := 1; i < len(r.PeerCertificates); i++ {
		RawSubjectSHA256 := GetCertFingerprint("SHA256", r.PeerCertificates[i].RawSubject)
		RawIssuerSHA256 := GetCertFingerprint("SHA256", r.PeerCertificates[i].RawIssuer)
		// We do not want root Certs to the intermediate pool
		if RawIssuerSHA256 != RawSubjectSHA256 {
			localIntermediatePool.AddCert(r.PeerCertificates[i])
		}
	}

	localVerifyOptions := x509.VerifyOptions{
		DNSName:                   dnsName,
		Intermediates:             localIntermediatePool,
		Roots:                     nil,
		CurrentTime:               time.Time{},
		KeyUsages:                 nil,
		MaxConstraintComparisions: 0,
	}

	if tlsToolConfig.NoUseTLSIntermediates == true {
		localVerifyOptions.Intermediates = nil
	}

	defaultChains, defaultChainsErr := leafCert.Verify(localVerifyOptions)

	if defaultChainsErr != nil {
		log.Fatal("An error occurred whilst trying to create chains with the provided certificates from the tls"+
			" connection ", defaultChainsErr)
	}

	fmt.Println("Default Certificate Chains(s) that were able to be built using certificates received from TLS" +
		" handshake.")
	fmt.Println("NOTE: Some operating system (e.g. windows) can provide extra intermediate certificates than" +
		" those provided from the TLS handshake for use in chain building.")
	fmt.Println()
	defaultConvertedChains, defaultConvertedChainsErr := ConvertChains(defaultChains)
	cbr.DefaultChains = defaultConvertedChains
	if defaultConvertedChainsErr != nil {
		log.Fatal("An error occurred trying to create default chains:", defaultConvertedChainsErr.Error())
	}
	for chainI, chain := range defaultConvertedChains {
		fmt.Println("Chain: " + strconv.Itoa(chainI+1))
		for ci, c := range chain {
			chainLen := len(chain)
			if ci == 0 {
				fmt.Println("Peer/Leaf Cert:")
			} else if ci == chainLen-1 {
				fmt.Println("Root Cert:")
			} else {
				fmt.Println("Intermediate Cert:")
			}
			fmt.Println(GetCertSummaryString(c))
			fmt.Println()
		}
		fmt.Println("######################")
		fmt.Println()
	}

	if rootCertPool != nil || intermediateCertPool != nil {
		customPoolChains, customPoolChainsErr := leafCert.Verify(x509.VerifyOptions{
			DNSName:       dnsName,
			Intermediates: intermediateCertPool,
			CurrentTime:   time.Time{},
			Roots:         rootCertPool,
		})

		if customPoolChainsErr != nil {
			log.Fatal("An error occurred whilst trying to create chains with the provided certificates from the"+
				" local certificate directory specified from the command line arg -d/--cert-dir", customPoolChainsErr)
		}

		log.Println("Custom Certificate Chains(s) that were able to be built using certificates received from the" +
			" local certificate directory specified from the command line arg -d/--cert-dir.")
		customPoolConvertedChains, customPoolConvertedChainsErr := ConvertChains(customPoolChains)
		if defaultConvertedChainsErr != nil {
			log.Fatal("An error occurred trying to create custom pool chains:", customPoolConvertedChainsErr.Error())
		}
		cbr.CustomPoolChains = customPoolConvertedChains
		for chainI, chain := range customPoolConvertedChains {
			fmt.Println("Chain: " + strconv.Itoa(chainI+1))
			for ci, c := range chain {
				chainLen := len(chain)
				if ci == 0 {
					fmt.Println("Peer/Leaf Cert:")
				} else if ci == chainLen-1 {
					fmt.Println("Root Cert:")
				} else {
					fmt.Println("Intermediate Cert:")
				}
				fmt.Println(GetCertSummaryString(c))
				fmt.Println()
			}
			fmt.Println("######################")
			fmt.Println()
		}
	}
}

func GetCertSummaryString(c *ChainLink) string {
	var certFields []string
	var certSummaryString string
	if tlsToolConfig.printCertFields == "" {
		certFields = []string{"subject", "issuer", "notBefore", "notAfter", "ski", "aki"}
	} else {
		certFields = processCertFields(tlsToolConfig.printCertFields)
	}
	certSummaryStringSperator := "\n"
	for _, certField := range certFields {
		switch certField {
		case "subject":
			certSummaryString += "Subject: " + c.Subject + certSummaryStringSperator
		case "issuer":
			certSummaryString += "Issuer: " + c.Issuer + certSummaryStringSperator
		case "ski":
			certSummaryString += "SKI: " + c.SubjectKeyIdentifier + certSummaryStringSperator
		case "aki":
			certSummaryString += "AKI: " + c.AuthorityKeyIdentifier + certSummaryStringSperator
		case "notBefore":
			certSummaryString += "NotBefore: " + c.NotBefore + certSummaryStringSperator
		case "notAfter":
			certSummaryString += "NotAfter: " + c.NotAfter + certSummaryStringSperator
		case "certMD5":
			certSummaryString += "certMD5 " + c.CertFingerprints.MD5 + certSummaryStringSperator
		case "certSHA1":
			certSummaryString += "certSHA1: " + c.CertFingerprints.SHA1 + certSummaryStringSperator
		case "certSHA256":
			certSummaryString += "certSHA256: " + c.CertFingerprints.SHA256 + certSummaryStringSperator
		case "dnsNames":
			certSummaryString += "dnsNames: "
			for _, dnsName := range c.DNSNames {
				certSummaryString += dnsName + ","
			}
			certSummaryString = strings.Trim(certSummaryString, ",")
		case "emailAddresses":
			certSummaryString += "emailAddresses: "
			for _, emailAddress := range c.EmailAddresses {
				certSummaryString += emailAddress + ","
			}
			certSummaryString = strings.Trim(certSummaryString, ",")
		case "uris":
			certSummaryString += "uris: "
			for _, uri := range c.URIs {
				certSummaryString += uri + ","
			}
			certSummaryString = strings.Trim(certSummaryString, ",")
		case "keyUsage":
			certSummaryString += "uris: "
			for _, keyUsage := range c.KeyUsage {
				certSummaryString += keyUsage.Name + ","
			}
			certSummaryString = strings.Trim(certSummaryString, ",")
		case "extraKeyUsage":
			certSummaryString += "uris: "
			for _, extraKeyUsage := range c.ExtraKeyUsage {
				certSummaryString += extraKeyUsage.Name + "(oid: " + extraKeyUsage.Oid + "),"
			}
			certSummaryString = strings.Trim(certSummaryString, ",")
		case "certPEM":
			certSummaryString += "certPem: " + c.CertPem + "\n"
		}
	}
	certSummaryString = strings.Trim(certSummaryString, certSummaryStringSperator)
	return certSummaryString
}

func processCertFields(certFields string) []string {
	var certFieldsList []string
	certFields = strings.Trim(certFields, ",")
	certFieldsSplit := strings.Split(certFields, ",")
	for _, certField := range certFieldsSplit {
		if _, ok := certFieldsMap[certField]; ok {
			certFieldsList = append(certFieldsList, certField)
		} else {
			log.Fatal("Unknown field '"+certField+"' . Allowed fields: ", getAllowedCertFields())
		}
	}
	return certFieldsList
}

func getAllowedCertFields() string {
	var allowedCertFieldsStr string
	for certField := range certFieldsMap {
		allowedCertFieldsStr += certField + ", "
	}
	allowedCertFieldsStr = strings.Trim(allowedCertFieldsStr, ", ")
	return allowedCertFieldsStr
}

func CreateChainLink(c *x509.Certificate) *ChainLink {
	cl := ChainLink{
		Subject:                c.Subject.String(),
		Issuer:                 c.Issuer.String(),
		DNSNames:               c.DNSNames,
		EmailAddresses:         c.EmailAddresses,
		NotBefore:              c.NotBefore.UTC().Format("2006-01-02T15:04:05 -0700"),
		NotBeforeEpoch:         c.NotBefore.Unix(),
		NotAfter:               c.NotAfter.UTC().Format("2006-01-02T15:04:05 -0700"),
		NotAfterEpoch:          c.NotAfter.Unix(),
		SubjectKeyIdentifier:   BytesToHexWithSeparator(c.SubjectKeyId, ':'),
		AuthorityKeyIdentifier: BytesToHexWithSeparator(c.AuthorityKeyId, ':'),
		CertFingerprints: CertFingerprints{
			MD5:    GetCertFingerprint("MD5", c.Raw),
			SHA1:   GetCertFingerprint("SHA1", c.Raw),
			SHA256: GetCertFingerprint("SHA256", c.Raw),
		},
		CertPem: x509ToPem(c),
	}
	for _, ip := range c.IPAddresses {
		cl.IPAddresses = append(cl.IPAddresses, ip.String())
	}
	for _, uri := range c.URIs {
		cl.IPAddresses = append(cl.IPAddresses, uri.String())
	}
	for _, eku := range c.ExtKeyUsage {
		cl.ExtraKeyUsage = append(cl.ExtraKeyUsage, GetExtKeyUsageDetail(eku))
	}
	for _, ku := range keyUsageList {
		if HasBit(int(c.KeyUsage), int(ku)) == true {
			cl.KeyUsage = append(cl.KeyUsage, GetKeyUsageDetail(ku))
		}
	}
	return &cl
}

func ConvertChains(chains [][]*x509.Certificate) (newChainsFormat [][]*ChainLink, err error) {
	for _, chain := range chains {
		var newChainFormat []*ChainLink
		for _, c := range chain {
			newChainFormat = append(newChainFormat, CreateChainLink(c))
		}
		if newChainFormat != nil {
			newChainsFormat = append(newChainsFormat, newChainFormat)
		}
	}
	return newChainsFormat, nil
}

func x509ToPem(c *x509.Certificate) (certPem string) {
	maxLineLength := 64
	cStr := base64.StdEncoding.EncodeToString(c.Raw)
	cStrLen := len(cStr)
	certPem += "-----BEGIN CERTIFICATE-----\n"
	cursorPosition := 0
	for {
		if cursorPosition+maxLineLength >= cStrLen {
			certPem += cStr[cursorPosition:cStrLen] + "\n"
			break
		}
		certPem += cStr[cursorPosition:cursorPosition+maxLineLength] + "\n"
		cursorPosition += maxLineLength
	}
	certPem += "-----END CERTIFICATE-----\n"
	return certPem
}

func CreateCertPoolFromDir(pemCertsDir string, certType string) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()
	numCertsAdded := 0
	// Check is pemCertsDir is a file object
	fileInfo, fileInfoErr := os.Stat(pemCertsDir)
	if fileInfoErr != nil {
		return nil, fileInfoErr
	}

	// Throw error if file pemCertsDir is of type dir
	if !fileInfo.IsDir() {
		return nil, errors.New("pemCertsDir: " + pemCertsDir + " is not a dir")
	}

	pemCertFiles, listPemCertsDirErr := ioutil.ReadDir(pemCertsDir)
	if listPemCertsDirErr != nil {
		return nil, listPemCertsDirErr
	}

	for _, pemCertFile := range pemCertFiles {
		filePath := filepath.Join(pemCertsDir, pemCertFile.Name())

		pemCerts, pemCertFileDataErr := ioutil.ReadFile(filePath)
		if pemCertFileDataErr != nil {
			//log.Println(pemCertFileDataErr)
			return nil, pemCertFileDataErr
		}

		for len(pemCerts) > 0 {
			var block *pem.Block
			block, pemCerts = pem.Decode(pemCerts)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				continue
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}
			if CheckCertAllowed(cert, certType) == false {
				fmt.Println(false, filePath)
				continue
			}
			certPool.AddCert(cert)
			numCertsAdded += 1
		}
	}

	// If there were not any certs added to the pool then return nil
	fmt.Println(strconv.Itoa(numCertsAdded) + " certificates have been added to the " + certType + " pool.")
	if numCertsAdded == 0 {
		certPool = nil
	}
	return certPool, nil
}

func CheckCertAllowed(cert *x509.Certificate, certType string) bool {
	if certType == "root" || certType == "intermediate" {
		certificateFingerprint := GetCertFingerprint("SHA256", cert.Raw)
		// KeyUsageCertSign and KeyUsageCRLSign should be on root and intermediate certs
		if (!HasBit(int(cert.KeyUsage), int(x509.KeyUsageCertSign)) ||
			!HasBit(int(cert.KeyUsage), int(x509.KeyUsageCRLSign))) && int(cert.KeyUsage) != 0 {
			fmt.Println("Not adding certificate with SHA256 Fingerprint: " + certificateFingerprint +
				" as KeyUsageCertSign or KeyUsageCRLSign are not present." +
				" KeyUsage (base 10 int): " + strconv.Itoa(int(cert.KeyUsage)))
			return false
		}
		issuerFingerprint := GetCertFingerprint("SHA256", cert.RawIssuer)
		subjectFingerprint := GetCertFingerprint("SHA256", cert.RawSubject)
		// Issue and Subject must match if it is a root and the reverse if it is an intermediate
		if issuerFingerprint != subjectFingerprint && certType == "root" {
			fmt.Println("Not adding cert SHA256Fingerprint: " + certificateFingerprint + " to " + certType + " pool" +
				" as issuer '" + cert.Issuer.String() + "' with SHA256 Fingerprint: " + issuerFingerprint +
				" does not match subject '" + cert.Subject.String() + "' subjectFingerprint: " + subjectFingerprint +
				" For root certificates the subject and issuer should match.")
			return false
		} else if issuerFingerprint == subjectFingerprint && certType == "intermediate" {
			fmt.Println("Not adding cert SHA256Fingerprint: " + certificateFingerprint + " to " + certType + " pool" +
				" as issuer '" + cert.Issuer.String() + "' with SHA256 Fingerprint: " + issuerFingerprint +
				" does matches subject '" + cert.Subject.String() + "' subjectFingerprint: " + subjectFingerprint +
				" For intermediate certificates the subject and issuer should not match.")
			return false
		}
	}
	return true
}

func constructTLSConfig(evalTime time.Time) *tls.Config {
	if tlsToolConfig.Address == "" {
		log.Fatal("Address (-a/--address) must be specified. Use -h/--help for more information.")
	}

	if tlsToolConfig.TLSVersion != "" && (tlsToolConfig.TLSMinVersion != "" || tlsToolConfig.TLSMaxVersion != "") {
		log.Fatal("-T/--tls-version cannot be used with -u/--tls-min-version or -x/--tls-max-version")
	}

	cfg := &tls.Config{
		InsecureSkipVerify: tlsToolConfig.InsecureSkipVerify,
		Time: func() time.Time {
			return evalTime
		},
	}

	if tlsToolConfig.TLSVersion != "" {
		tlsVersionUint16, tlsVersionUint16Err := getTLSVersionFromString(tlsToolConfig.TLSVersion)
		if tlsVersionUint16Err != nil {
			log.Fatal("-T/--tls-version ", tlsVersionUint16Err.Error())
		}
		cfg.MinVersion = tlsVersionUint16
		cfg.MaxVersion = tlsVersionUint16
	} else {
		if tlsToolConfig.TLSMinVersion != "" {
			tlsMinVersionUint16, tlsMinVersionUint16Err := getTLSVersionFromString(tlsToolConfig.TLSMinVersion)
			if tlsMinVersionUint16Err != nil {
				log.Fatal("-u/--tls-min-version ", tlsMinVersionUint16Err.Error())
			}
			cfg.MinVersion = tlsMinVersionUint16
		}
		if tlsToolConfig.TLSMaxVersion != "" {
			tlsMaxVersionUint16, tlsMaxVersionUint16Err := getTLSVersionFromString(tlsToolConfig.TLSMaxVersion)
			if tlsMaxVersionUint16Err != nil {
				log.Fatal("-x/--tls-max-version ", tlsMaxVersionUint16Err.Error())
			}
			cfg.MaxVersion = tlsMaxVersionUint16
		}
	}

	// Servername is the string that will be used by the target address Server Name Indication
	// Servername is used in the TLS handshake process (Client Hello)
	// https://www.cloudflare.com/learning/ssl/what-is-sni/
	if tlsToolConfig.Servername != "" {
		cfg.ServerName = tlsToolConfig.Servername
	} else {
		cfg.ServerName = tlsToolConfig.Address
	}
	return cfg
}

func getSupportedTLSVersionsString() string {
	supportedVersions := ""
	for v := range tlsVersionsMap {
		supportedVersions += v + ", "
	}
	supportedVersions = strings.Trim(supportedVersions, ", ")
	return supportedVersions
}

func getTLSVersionFromString(tlsVersionString string) (uint16, error) {
	if _, ok := tlsVersionsMap[tlsVersionString]; ok {
		return tlsVersionsMap[tlsVersionString], nil
	} else {
		return 0, errors.New("Unknown TLS Version: '" + tlsVersionString + "'." +
			" Supported versions are: " + getSupportedTLSVersionsString())
	}
}

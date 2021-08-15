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
func doTLS(address string, port string, tcpDialTimeout time.Duration, tlsHandshakeTimeout time.Duration,
) (*TLSInfo, error) {
	var tlsInfo TLSInfo

	cfg := constructTLSConfig()

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
		log.Fatal("No certificates provided on the TLS connection for address: " + tlsToolConfig.Address + ".")
	}

	log.Println("Certificate(s) received from the TLS connection:")
	for i, c := range r.PeerCertificates {
		peerCertConverted := CreateChainLink(c)
		cbr.PeerCertificates = append(cbr.PeerCertificates, peerCertConverted)
		fmt.Println("["+strconv.Itoa(i)+"]", GetCertSummaryString(peerCertConverted))
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

	if tlsToolConfig.NoUseTLSIntermediates == 1 {
		localVerifyOptions.Intermediates = nil
	}

	defaultChains, defaultChainsErr := leafCert.Verify(localVerifyOptions)

	if defaultChainsErr != nil {
		log.Fatal("An error occurred whilst trying to create chains with the provided certificates from the tls"+
			" connection ", defaultChainsErr)
	}

	log.Println("Certificate Chains(s) the were able to be built using certificates received from TLS connection" +
		" in the format: [chain_index][certificate_index] <certificate information>")
	fmt.Println("NOTE: Some operating system (e.g. windows) can provide extra intermediate certificates than" +
		" those provided from the TLS connection for use in chain building.")
	defaultConvertedChains, defaultConvertedChainsErr := ConvertChains(defaultChains)
	cbr.DefaultChains = defaultConvertedChains
	if defaultConvertedChainsErr != nil {
		log.Fatal("An error occurred trying to create default chains:", defaultConvertedChainsErr.Error())
	}
	for chainI, chain := range defaultConvertedChains {
		for ci, c := range chain {
			fmt.Println("["+strconv.Itoa(chainI)+"]["+strconv.Itoa(ci)+"]", GetCertSummaryString(c))
		}
		fmt.Println()
	}

	if rootCertPool != nil || intermediateCertPool != nil {
		customPoolChains, customPoolChainsErr := leafCert.Verify(x509.VerifyOptions{
			DNSName:       dnsName,
			Intermediates: intermediateCertPool,
			// Need to check the cert wsa valid when the website was scanned
			CurrentTime: time.Time{},
			Roots:       rootCertPool,
		})

		if customPoolChainsErr != nil {
			log.Fatal("An error occurred whilst trying to create chains with the provided certificates from the"+
				" local certificate directory specified from the command line arg -d/--cert-dir", customPoolChainsErr)
		}

		log.Println("Certificate Chains(s) the were able to be built using certificates received from the" +
			" local certificate directory specified from the command line arg -d/--cert-dir in the format:" +
			" [chain_index][certificate_index] <certificate information>")
		customPoolConvertedChains, customPoolConvertedChainsErr := ConvertChains(customPoolChains)
		if defaultConvertedChainsErr != nil {
			log.Fatal("An error occurred trying to create custom pool chains:", customPoolConvertedChainsErr.Error())
		}
		cbr.CustomPoolChains = customPoolConvertedChains
		for chainI, chain := range customPoolConvertedChains {
			for ci, c := range chain {
				fmt.Println("["+strconv.Itoa(chainI)+"]["+strconv.Itoa(ci)+"]", GetCertSummaryString(c))
			}
			fmt.Println()
		}
	}
}

func GetCertSummaryString(c *ChainLink) string {
	certSummaryString := ""
	certSummaryString += "Subject: " + c.Subject + ", "
	certSummaryString += "SKI: " + c.SubjectKeyIdentifier + ", "
	certSummaryString += "AKI: " + c.AuthorityKeyIdentifier + ", "
	certSummaryString += "NotAfter: " + c.NotAfter + ", "
	certSummaryString += "SHA1: " + c.CertFingerprints.SHA1
	return certSummaryString
}

func CreateChainLink(c *x509.Certificate) *ChainLink {
	cl := ChainLink{
		Subject:                c.Subject.String(),
		Issuer:                 c.Issuer.String(),
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

	files := 0
	for _, pemCertFile := range pemCertFiles {
		files += 1
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
				log.Println(false, filePath)
				continue
			}
			certPool.AddCert(cert)
			numCertsAdded += 1
		}
	}

	// If there were not any certs added to the pool then return nil
	if numCertsAdded == 0 {
		certPool = nil
	}
	return certPool, nil
}

func CheckCertAllowed(cert *x509.Certificate, certType string) bool {
	if certType == "root" || certType == "intermediate" {
		ch := GetCertFingerprint("SHA256", cert.Raw)
		// KeyUsageCertSign and KeyUsageCRLSign should be on root and intermediate certs
		if (!HasBit(int(cert.KeyUsage), int(x509.KeyUsageCertSign)) ||
			!HasBit(int(cert.KeyUsage), int(x509.KeyUsageCRLSign))) && int(cert.KeyUsage) != 0 {
			log.Println("Not adding cert KeyUsageCertSign or KeyUsageCRLSign not present." +
				" KeyUsage: " + strconv.Itoa(int(cert.KeyUsage)) + ". SHA256Fingerprint: " + ch)
			return false
		}
		ih := GetCertFingerprint("SHA256", cert.RawIssuer)
		sh := GetCertFingerprint("SHA256", cert.RawSubject)
		// Issue and Subject must match if it is a root and the reverse if it is an intermediate
		if (ih != sh && certType == "root") || (ih == sh && certType == "intermediate") {
			log.Println("Not adding cert SHA256Fingerprint: " + ch + " to pool. ih: " + ih +
				", sh: " + sh + ", certType: " + certType)
			return false
		}
	}
	return true
}

func constructTLSConfig() *tls.Config {

	if tlsToolConfig.Address == "" {
		log.Fatal("Address (-a/--address) must be specified. Use -h/--help for more information.")
	}

	cfg := &tls.Config{
		InsecureSkipVerify: tlsToolConfig.InsecureSkipVerify,
	}
	//fmt.Println(tlsVersionsMap)
	if _, ok := tlsVersionsMap[tlsToolConfig.TLSMinVersion]; ok {
		cfg.MinVersion = tlsVersionsMap[tlsToolConfig.TLSMinVersion]
	} else if tlsToolConfig.TLSMinVersion != "" {
		log.Fatal("Unknown TLSMinVersion: '" + tlsToolConfig.TLSMinVersion + "' (-u/--tls-min-version)." +
			" Supported versions are: " + getSupportedTLSVersionsString())
	}

	if _, ok := tlsVersionsMap[tlsToolConfig.TLSMaxVersion]; ok {
		cfg.MaxVersion = tlsVersionsMap[tlsToolConfig.TLSMaxVersion]
	} else if tlsToolConfig.TLSMaxVersion != "" {
		log.Fatal("Unknown TLSMaxVersion: '" + tlsToolConfig.TLSMaxVersion + "' (-x/--tls-max-version)." +
			" Supported versions are: " + getSupportedTLSVersionsString())
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

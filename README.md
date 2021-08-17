# goTLSTool
A Tool for analysis in the TLS realm


# Installation
Currently, this tool is not in any package repositories. The latest version can be found in the
[releases section](https://github.com/cyber-inspector/go_tls_tool/releases).

# Usage
There are no configuration file(s) required. Command line
arguments are the exclusive way to manipulate this tool.

## Command Line Arguments
- mode: `-m/--mode`
  - Required: `true`
  - Type: `string`
  - Allowed Values: `chains` `tlsVersion`
  - Description: Which mode to use. See [modes](#modes)
- version: `-v/--version`
  - Required: `false`
  - Type: `bool`
  - Allowed Values: No values can be provided as this changes the default state of false to true
  - Description: Display the version of this application
- Address: `-a/--address`
  - Required: `false`
  - Type: `string`
  - Allowed Values: No restriction
  - Description: Address for opening tcp connection e.g www.example.com. 
An ip address can also be used (e.g. `192.168.0.2`).
Servername (`-s/--servername`) can be used to specify the
servername used for the TLS [SNI](https://www.cloudflare.com/learning/ssl/what-is-sni/)
extension.
- Port: `-p/--port`
  - Required: `false`
  - Type: `int`
  - Allowed Values: Any int between 1 and 65535
  - Description: Port to use for the tcp connection (e.g. `443`). Default value `443`. If port set to
0 it will be changed to `443`.
- Servername: `-s/--servername`
  - Required: `false`
  - Type: `string`
  - Allowed Values: No restriction
  - Description: Name used for TLS [SNI](https://www.cloudflare.com/learning/ssl/what-is-sni/)
extension and certificate verification.
If not specified the value for (-a/--address) will be used.
- CertDir: `-d/--cert-dir`
  - Required: `false`
  - Type: `string`
  - Allowed Values: No restriction
  - Description: Path to the directory that contains the folders `root` and `intermediate`
to load certificates for extra/specific chain building.
  - For more information about custom certificate pools please see [here](#custom-certificate-pools)
  - NOTE: only used for mode `chains`
- NoUseTLSIntermediates: `-n/no-use-tls-intermediates`
  - Required: `false`
  - Type: `bool`
  - Allowed Values: No values can be provided as this changes the default state of false to true
  - Description: Do not use the intermediate(s) provided by the TLS handshake
for the construction of default TLS chains. NOTE: only used for mode: chains
- InsecureSkipVerify: `-i/--insecure-skip-verify`
  - Required: `false`
  - Type: `bool`
  - Allowed Values: No values can be provided as this changes the default state of false to true
  - Description: Set tls.Config.InsecureSkipVerify to true i.e. accept any certificate provided to allow a TLS
    connection to be established.
- TLSMinVersion: `-u/--tls-min-version`
  - Required: `false`
  - Type: `string`
  - Allowed Values: `TLS10` `TLS11` `TLS12` `TLS13`
  - Description: Minimum TLS version to use in handshake. If only a single tls version is desired set
`-u/--tls-min-version` and `-u/--tls-max-version` to the same value.
- TLSMaxVersion: `-u/--tls-max-version`
  - Required: `false`
  - Type: `string`
  - Allowed Values: `TLS10` `TLS11` `TLS12` `TLS13`
  - Description: Maximum TLS version to use in handshake. If only a single tls version is desired set
    `-u/--tls-min-version` and `-u/--tls-max-version` to the same value.
- TLSMaxVersion: `-T/--tls-version`
  - Required: `false`
  - Type: `string`
  - Allowed Values: `TLS10` `TLS11` `TLS12` `TLS13`
  - Description: Sole TLS version to use in handshake
- DumpResult: `-o/--dump-result`
  - Required: `false`
  - Type: `bool`
  - Allowed Values: No values can be provided as this changes the default state of false to true
  - Description: Dump the output to a file in the format: <mode>-<address>-<servername>-<epochTimeSeconds<.json
- PrintCerts: `-t/--print-certs`
  - Required: `false`
  - Type: `bool`
  - Allowed Values: No values can be provided as this changes the default state of false to true
  - Description: Print the certificates from the TLS handshake to the console.
- PrintCertsFields: `-F/--print-cert-fields`
  - Required: `false`
  - Type: `string`
  - Allowed Values: notBefore, dnsNames, ski, emailAddresses, uris, extraKeyUsage, certPEM, aki, certSHA1, notAfter, certMD5, certSHA256, keyUsage, subject, issuer
  - Description: CSL (comma seperated list) of fields from the x509 certificate to print to the console.
    This applies to -t/-print-certs and chains mode.

# Modes
## tlsVersion
Try and establish a TLS connection and display the version and cipher suite negotiated along with the certificate(s)
from the TLS handshake. `TLSMinVersion` and `TLSMinVersion` can be used to specify which TLS versions can be used for
the TLS connection.

## chains
### Default Chains
Build as many chains as possible with the certificate(0)s provided on the TLS handshake against the
default operating system trust store.
- Windows (and potentially other operating systems) can provide extra intermediate certificates other 
than those from the TLS handshake. There is no method (as yet), for this tool to prevent this from 
occurring.
- The command line argument `-n/no-use-tls-intermediates` can be used to show chains that are built
from only intermediates the operating system provides. i.e. not using the intermediate certificates from the 
TLS handshake.

### Custom Pool Chains
If `-d/--cert-dir` is specified the tool will try and build two certificate pools from this directory.
One for intermedia certificates one for root certificates.
- One or both of these pools (root/intermediate) must have at least one certificate for chains to be
attempted to be built.
- For more information about custom certificate pools please see [here](#custom-certificate-pools)

# Custom Certificate Pools
`-d/--cert-dir` can be optionally used to specify a directory containing root/intermediate certificates.
- The intent of these pools is for use only during custom chain generation. See `Custom Pool Chains`
in the section `Modes`
- There should be two subdirectories in the directory specified by `-d/--cert-dir`
  - `root` which should contain `root` certificate files in the `PEM` format
  - `intermediate` which should contain `intermediate` certificate files in the `PEM` format
- If an `intermediate` certificate is placed in the `root` subdirectory, or visa versa, a message
should be displayed and the certificate in question will not be added to either pool

# Examples
## tlsVersion
### Determine the TLS version negotiated to `example.com` without restricting to specific TLS version(s)
```shell
$ goTLSTool --mode tlsVersion --address example.com
```
### Determine the TLS version negotiated to `example.com` without restricting to specific TLS version(s) and save
results to a file
```shell
$ goTLSTool --mode tlsVersion --address example.com --dump-result
```
### Determine the TLS version negotiated to  `example.com` restricting to TLS versions 1.0 - 1.2
```shell
$ goTLSTool --mode tlsVersion --address example.com --tls-min-version TLS10 --tls-max-version TLS12
```
### Determine the TLS version negotiated to `example.com` restricting to TLS versions 1.2 only
```shell
$ goTLSTool --mode tlsVersion --address example.com --tls-version TLS12
```
### Determine the TLS version negotiated to `example.com` with address `93.184.216.34` without restricting to specific TLS version(s)
```shell
$ goTLSTool --mode tlsVersion --address 93.184.216.34 --servername example.com
```
### Determine the TLS version negotiated to `example.com` with port `443` without restricting to specific TLS version(s)
```shell
$ goTLSTool --mode tlsVersion --address example.com --port 443
```
### Determine the TLS version negotiated to `example.com` without restricting to specific TLS version(s) and print certificates
```shell
$ goTLSTool --mode tlsVersion --address example.com --print-certs
```
### Determine the TLS version negotiated to `example.com` without restricting to specific TLS version(s) and print certificates with fields issuer ski and aki
```shell
$ goTLSTool --mode tlsVersion --address example.com --print-certs --print-cert-fields subject,ski,aki
```
## chains
### Determine the default chains for `example.com`
```shell
$ goTLSTool --mode chains --address example.com
```
### Determine the default chains and custom chains for `example.com`
```shell
$ goTLSTool --mode chains --address example.com --cert-dir /path/to/certificates
```

# Limitations
## TLS Versions Supported
- TLS v1.0
- TLS v1.1
- TLS v1.2
- TLS v1.3

## TLS 1.0 - 1.2 Cipher Suites supported
- TLS_RSA_WITH_RC4_128_SHA
- TLS_RSA_WITH_3DES_EDE_CBC_SHA
- TLS_RSA_WITH_AES_128_CBC_SHA
- TLS_RSA_WITH_AES_256_CBC_SHA
- TLS_RSA_WITH_AES_128_CBC_SHA256
- TLS_RSA_WITH_AES_128_GCM_SHA256
- TLS_RSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
- TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
- TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
- TLS_ECDHE_RSA_WITH_RC4_128_SHA
- TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
- TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
- TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
- TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
- TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
- TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256

## TLS 1.3 Cipher Suites supported
- TLS_AES_128_GCM_SHA256
- TLS_AES_256_GCM_SHA384
- TLS_CHACHA20_POLY1305_SHA256

# Contribution

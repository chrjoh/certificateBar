certificateBar
=========
Initial setup, the goal is to create a simple tool to generate certificate and chains to perform test in
development/stage environments. The setup should allow you to be able to change key types,
key usage and other parameters on the certificates to verify that the test setup is working.
The configurations will be aimed to remove some of the "magic" that people find then working with PKI and
certificates. The project is work in progress.

On a side note is the interesting announcement from NSA regaring elliptic curve crypto, see
http://eprint.iacr.org/2015/1018.pdf
## Dependencies

## Installation

```bash
$ go get -u github.com/chrjoh/certificatebar
```

## Usage
```bash
$ certificatebar --help

Command line arguments:

  -i configuration file to be used
```

## Config
The structure of the config file is given bellow, certificates label conatins a list of certificate.
(See config directory for a basic example setup.) The example below is a self signed certificate valid
for domains `www.foo.se, www.dront.se, www.fro.se` and using a 2048 RSA key.
```
certificates:
  - certificate:
      id: mainca
      parent: mainca
      ca: true
      pkix:
        commonname: www.foo.se
        country: SE
        organization: test
        organizationunit: testca
      altnames:
        - www.dront.se
        - www.fro.se
      keytype: RSA
      keylength: 2048
      hashalg: SHA256
      validfrom: 2010-01-01
      validto: 2020-01-01
```
The options for each keywords is

| keyword | required | description | options |
|---------|----------|-------------|---------|
| id      |    *     | id used to identify the certificate and also the name used then saving the certificate and the private key to a file | string: mainca |
| parent  |    *     | certificate to be used then signing, must be a valid id | string: mainca |
| ca      |    *     | is this certificate used to sign other certificates| boolean: true or false |
| keytype |    *     | key type to be used| string: RSA, P224, P256, P384, P512 |
| commonname |       | the common name this certificate shoud have | string: www.foo.se |
| country    |       | the country code to use | string:  SE |
| organization |     | organisation name | string:  test |
| organizationunit|  | organisation unit to be used | string: testca |
| altnames        |  | list of alternative DNS names this certificate is valid for | string: valid dns names |
| keylength       |  | key length, only used with RSA key, default is 2048 | int: 2048 |
| hashalg         |  | which algorithm to be used for signature, default is SHA256 | string: SHA1, SHA256, SHA384, SHA512 |
| validfrom       |  | Start date then the certificate is valid, default is now | string: 2010-01-01 |
| validto         |  | End date then the certificate is not valid, default is 1 year | string: 2020-01-01 |
## License (MIT)

Copyright (c) 2015 [Christer Johansson](http://blog.lodakai.com/)

> Permission is hereby granted, free of charge, to any person obtaining
> a copy of this software and associated documentation files (the
> "Software"), to deal in the Software without restriction, including
> without limitation the rights to use, copy, modify, merge, publish,
> distribute, sublicense, and/or sell copies of the Software, and to
> permit persons to whom the Software is furnished to do so, subject to
> the following conditions:

> The above copyright notice and this permission notice shall be
> included in all copies or substantial portions of the Software.

> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
> EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
> MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
> NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
> LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
> OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
> WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

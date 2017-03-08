clone-cert.sh
=============

This is a simple shell script that reads the subject and issuer of an X.509
certificate associated with an SSL wrapped TCP port and uses `openssl` to
create a similar certificate with the same subject and the same issuer. This
is particularly useful if you want to demonstrate why self-signed
certificates cannot provide any security. Of course, the fingerprint of the
cloned certificate will be different... but who checks the fingerprint of a
self-signed certificate by hand?

Example
-------

Run the script:

    $ ./clone-cert.sh www.example.com:443
    /tmp/www.example.com:443.key
    /tmp/www.example.com:443.cert

The new certificate is in `/tmp/www.example.com:443.cert` and the
corresponding private key is in `/tmp/www.example.com:443.key`.


This is the cloned certificate:

	$ openssl x509 -text -in /tmp/www.example.com:443.cert -noout
	Certificate:
		Data:
			Version: 1 (0x0)
			Serial Number: 0 (0x0)
		Signature Algorithm: sha256WithRSAEncryption
			Issuer: C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert SHA2 High Assurance Server CA
			Validity
				Not Before: Mar  7 13:09:08 2017 GMT
				Not After : Nov 27 13:09:08 2018 GMT
			Subject: C = US, ST = California, L = Los Angeles, O = Internet Corporation for Assigned Names and Numbers, OU = Technology, CN = www.example.org
			Subject Public Key Info:
				Public Key Algorithm: rsaEncryption
					Public-Key: (1024 bit)
					Modulus:
						00:a0:1e:88:3d:0c:82:51:41:cc:73:21:17:57:fa:
						fc:ce:36:3b:49:db:0d:dc:33:d8:1f:6d:a9:9e:dc:
						c6:8a:81:e3:b8:6d:d5:bb:5a:57:e2:49:30:bf:15:
						50:2b:31:14:3b:55:78:6f:80:47:0c:89:6d:d2:eb:
						72:33:85:43:5e:d3:a9:87:56:cf:3f:ba:6d:84:3e:
						ea:f2:87:3b:cf:e0:c4:e3:e1:f5:d5:00:2a:69:38:
						74:ea:45:4c:f3:d1:b8:7b:38:6a:b6:be:7b:7d:20:
						8b:d2:24:f9:47:49:14:da:74:40:0d:20:1a:9b:f2:
						51:f9:f6:e4:0c:d7:cb:3f:09
					Exponent: 65537 (0x10001)
		Signature Algorithm: sha256WithRSAEncryption
			 72:e8:0f:52:ba:8e:10:db:e0:31:e6:a9:90:0a:38:aa:d7:54:
			 0c:e9:cd:b9:86:38:3c:4c:00:0e:2c:6e:b7:e7:b1:10:5e:67:
			 cd:84:02:00:88:f1:85:1e:be:60:35:b8:15:71:87:5d:b9:44:
			 aa:39:c0:b8:95:a4:06:2b:38:1f:63:c4:ab:3d:5d:ae:0a:a3:
			 19:1c:24:80:98:99:83:0b:c7:fc:82:f6:3f:67:09:88:14:8d:
			 8d:88:54:95:c4:44:54:40:4c:3c:cb:7f:5b:1d:64:09:7e:d8:
			 c5:e0:00:45:c3:e9:1f:0a:e5:72:d5:7d:fa:5d:65:b6:37:89:
			 d3:ad

And this is the original certificate:

	$ openssl s_client -showcerts -connect www.example.com:443 < /dev/null 2> /dev/null | openssl  x509 -text -noout
	Certificate:
		Data:
			Version: 3 (0x2)
			Serial Number:
				0e:64:c5:fb:c2:36:ad:e1:4b:17:2a:eb:41:c7:8c:b0
		Signature Algorithm: sha256WithRSAEncryption
			Issuer: C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert SHA2 High Assurance Server CA
			Validity
				Not Before: Nov  3 00:00:00 2015 GMT
				Not After : Nov 28 12:00:00 2018 GMT
			Subject: C = US, ST = California, L = Los Angeles, O = Internet Corporation for Assigned Names and Numbers, OU = Technology, CN = www.example.org
			Subject Public Key Info:
				Public Key Algorithm: rsaEncryption
					Public-Key: (2048 bit)
					Modulus:
						00:b3:40:96:2f:61:63:3e:25:c1:97:ad:65:45:fb:
						ef:13:42:b3:2c:99:86:f4:b5:80:0b:76:dc:06:38:
						2c:1f:a3:62:55:5a:36:76:de:ae:5d:fc:e2:e5:b4:
						e6:ec:5d:ca:ee:ca:df:50:16:24:2c:ee:fc:9a:b6:
						8c:f6:a8:b3:ac:7a:08:7b:2a:1f:ad:5f:e7:fa:96:
						59:25:ab:90:b0:f8:c2:3f:13:04:26:74:68:0f:c6:
						78:2a:95:8a:5f:42:f2:0e:ed:52:a6:eb:68:23:89:
						e5:43:f8:6d:12:1b:62:42:7b:a8:05:f3:59:c4:5e:
						d6:c5:cc:46:c0:4b:19:b9:2d:4a:71:72:24:1e:5e:
						55:44:93:ab:78:a1:47:4d:a5:dc:07:5a:9c:67:f4:
						11:68:12:2f:d3:28:71:bc:ad:72:05:3c:16:75:d4:
						f8:72:58:ba:19:f1:dc:09:ed:f1:18:c6:92:2f:7d:
						bc:16:0b:37:8d:8a:ef:1b:6f:4f:b9:e0:7a:54:98:
						bf:b5:b6:cf:bb:aa:93:7f:0a:7f:1f:56:eb:a9:d8:
						e1:db:d5:39:d8:18:5b:d1:f2:64:33:d0:d6:c4:23:
						ff:09:ab:6d:71:ce:da:cf:c1:17:9c:23:be:2c:af:
						2f:92:1c:3f:90:08:89:58:f2:b1:e1:10:6f:83:2e:
						f7:9f
					Exponent: 65537 (0x10001)
			X509v3 extensions:
				X509v3 Authority Key Identifier:
					keyid:51:68:FF:90:AF:02:07:75:3C:CC:D9:65:64:62:A2:12:B8:59:72:3B

				X509v3 Subject Key Identifier:
					A6:4F:60:1E:1F:2D:D1:E7:F1:23:A0:2A:95:16:E4:E8:9A:EA:6E:48
				X509v3 Subject Alternative Name:
					DNS:www.example.org, DNS:example.com, DNS:example.edu, DNS:example.net, DNS:example.org, DNS:www.example.com, DNS:www.example.edu, DNS:www.example.net
				X509v3 Key Usage: critical
					Digital Signature, Key Encipherment
				X509v3 Extended Key Usage:
					TLS Web Server Authentication, TLS Web Client Authentication
				X509v3 CRL Distribution Points:

					Full Name:
					  URI:http://crl3.digicert.com/sha2-ha-server-g4.crl

					Full Name:
					  URI:http://crl4.digicert.com/sha2-ha-server-g4.crl

				X509v3 Certificate Policies:
					Policy: 2.16.840.1.114412.1.1
					  CPS: https://www.digicert.com/CPS
					Policy: 2.23.140.1.2.2

				Authority Information Access:
					OCSP - URI:http://ocsp.digicert.com
					CA Issuers - URI:http://cacerts.digicert.com/DigiCertSHA2HighAssuranceServerCA.crt

				X509v3 Basic Constraints: critical
					CA:FALSE
		Signature Algorithm: sha256WithRSAEncryption
			 84:a8:9a:11:a7:d8:bd:0b:26:7e:52:24:7b:b2:55:9d:ea:30:
			 89:51:08:87:6f:a9:ed:10:ea:5b:3e:0b:c7:2d:47:04:4e:dd:
			 45:37:c7:ca:bc:38:7f:b6:6a:1c:65:42:6a:73:74:2e:5a:97:
			 85:d0:cc:92:e2:2e:38:89:d9:0d:69:fa:1b:9b:f0:c1:62:32:
			 65:4f:3d:98:db:da:d6:66:da:2a:56:56:e3:11:33:ec:e0:a5:
			 15:4c:ea:75:49:f4:5d:ef:15:f5:12:1c:e6:f8:fc:9b:04:21:
			 4b:cf:63:e7:7c:fc:aa:dc:fa:43:d0:c0:bb:f2:89:ea:91:6d:
			 cb:85:8e:6a:9f:c8:f9:94:bf:55:3d:42:82:38:4d:08:a4:a7:
			 0e:d3:65:4d:33:61:90:0d:3f:80:bf:82:3e:11:cb:8f:3f:ce:
			 79:94:69:1b:f2:da:4b:c8:97:b8:11:43:6d:6a:25:32:b9:b2:
			 ea:22:62:86:0d:a3:72:7d:4f:ea:57:3c:65:3b:2f:27:73:fc:
			 7c:16:fb:0d:03:a4:0a:ed:01:ab:a4:23:c6:8d:5f:8a:21:15:
			 42:92:c0:34:a2:20:85:88:58:98:89:19:b1:1e:20:ed:13:20:
			 5c:04:55:64:ce:9d:b3:65:fd:f6:8f:5e:99:39:21:15:e2:71:
			 aa:6a:88:82


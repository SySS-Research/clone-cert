clone-cert.sh
=============

This is a simple shell script that retrieves the X.509 certificate
associated with a TLS wrapped TCP port and uses `openssl` to create a
similar certificate by replacing the public key and fixing the signature.

This is particularly useful if you want to demonstrate why self-signed
certificates cannot provide any security. Of course, the fingerprint of the
cloned certificate will be different... but who checks the fingerprint of a
self-signed certificate by hand?

You can also clone certificates that are not self-signed. In that case, the
serial number is replaced by a newly generated one (because browsers keep
track of the serial numbers they encounter and will notice that something
fishy is going on), and the issuer is changed (for the same reason). The
fake issuer will have the first capital letter O replace by a zero or a
lower case L replaced by a capital i or have the last character replaced by
a space and will thus look inconspicuous to a casual observer.

The new fake issueing CA will be generated on the fly unless you provide
one.

Certificates containing either an RSA or an EC public key are supported.
SNI is also supported. Run `./clone-cert.sh` for more information about the
usage.

Example
-------

Run the script:

    $ ./clone-cert.sh www.example.com:443
    /tmp/www.example.com:443_0.key
    /tmp/www.example.com:443_0.cert

The new certificate is in `/tmp/www.example.com:443_0.cert` and the corresponding
private key is in `/tmp/www.example.com:443_0.key`. Their difference is only in
the RSA modulus and the signature:

	$ diff <(openssl x509 -in /tmp/www.example.com:443_0.cert -noout -text) \
           <(openssl s_client -connect www.example.com:443 < /dev/null 2> /dev/null \
             | openssl x509 -noout -text)
	16,33c16,33
	<                     00:c3:59:26:a5:ed:1c:2b:75:3a:0c:a2:ab:49:43:
	<                     e8:1a:cd:24:64:4a:11:5a:fe:94:10:57:2a:af:f6:
	<                     28:a0:0a:32:3e:09:a2:1c:60:f0:39:62:40:78:3b:
	<                     9f:69:0e:ca:64:71:72:f5:00:16:ba:63:57:2b:85:
	<                     dd:fb:2b:93:28:7f:fe:77:9f:a6:ff:6e:38:9b:65:
	<                     94:c4:34:59:53:33:4d:47:58:88:e1:fb:55:c8:48:
	<                     6d:19:e6:f3:84:6d:34:cd:93:88:e5:d2:70:2c:bc:
	<                     cd:d6:f3:56:8a:7f:04:a5:b5:c6:8c:bd:f2:b5:ef:
	<                     d5:c7:ab:5a:83:ea:f2:b9:f6:9f:9e:73:55:bf:a2:
	<                     14:03:f4:01:3c:11:48:9c:da:69:7e:e4:9c:01:5b:
	<                     a7:03:2d:6c:dc:62:4a:72:ba:a5:18:5b:d5:64:4e:
	<                     8a:65:b5:f1:6f:fa:76:eb:8e:c0:5d:4a:44:bf:65:
	<                     6e:55:b1:1d:b4:dc:3f:56:db:5e:e4:2a:8b:e4:21:
	<                     53:90:28:87:14:85:9e:93:82:3b:3a:e0:0f:fc:b5:
	<                     35:46:52:db:6e:6e:11:68:78:9b:07:02:7d:12:49:
	<                     e9:8a:47:07:f9:74:59:5d:4f:13:b2:40:6b:82:b1:
	<                     08:ef:62:ef:92:b7:67:2d:6e:10:33:2f:8d:e8:aa:
	<                     25:2f
	---
	>                     00:b3:40:96:2f:61:63:3e:25:c1:97:ad:65:45:fb:
	>                     ef:13:42:b3:2c:99:86:f4:b5:80:0b:76:dc:06:38:
	>                     2c:1f:a3:62:55:5a:36:76:de:ae:5d:fc:e2:e5:b4:
	>                     e6:ec:5d:ca:ee:ca:df:50:16:24:2c:ee:fc:9a:b6:
	>                     8c:f6:a8:b3:ac:7a:08:7b:2a:1f:ad:5f:e7:fa:96:
	>                     59:25:ab:90:b0:f8:c2:3f:13:04:26:74:68:0f:c6:
	>                     78:2a:95:8a:5f:42:f2:0e:ed:52:a6:eb:68:23:89:
	>                     e5:43:f8:6d:12:1b:62:42:7b:a8:05:f3:59:c4:5e:
	>                     d6:c5:cc:46:c0:4b:19:b9:2d:4a:71:72:24:1e:5e:
	>                     55:44:93:ab:78:a1:47:4d:a5:dc:07:5a:9c:67:f4:
	>                     11:68:12:2f:d3:28:71:bc:ad:72:05:3c:16:75:d4:
	>                     f8:72:58:ba:19:f1:dc:09:ed:f1:18:c6:92:2f:7d:
	>                     bc:16:0b:37:8d:8a:ef:1b:6f:4f:b9:e0:7a:54:98:
	>                     bf:b5:b6:cf:bb:aa:93:7f:0a:7f:1f:56:eb:a9:d8:
	>                     e1:db:d5:39:d8:18:5b:d1:f2:64:33:d0:d6:c4:23:
	>                     ff:09:ab:6d:71:ce:da:cf:c1:17:9c:23:be:2c:af:
	>                     2f:92:1c:3f:90:08:89:58:f2:b1:e1:10:6f:83:2e:
	>                     f7:9f
	67,81c67,81
	<          66:9e:dc:08:c6:81:2e:91:80:d7:7a:27:a9:0f:fb:72:89:53:
	<          21:b8:37:e9:f1:d6:d2:e8:98:08:01:29:ef:eb:74:19:30:6f:
	<          b0:a0:8d:c3:09:ec:06:cf:65:59:0e:8f:45:a4:8f:70:b2:8a:
	<          a3:71:d8:0f:eb:87:95:be:ba:22:76:3d:3c:33:62:c4:28:34:
	<          6e:1a:be:de:8e:50:87:95:9c:85:ad:bf:91:b4:06:55:d6:b9:
	<          e2:f7:26:a1:5e:b9:57:f4:97:97:0f:08:9e:8f:36:6e:85:9c:
	<          aa:69:78:93:c0:aa:2a:ac:62:44:3f:eb:b3:4a:ee:6b:c9:63:
	<          91:af:64:3f:8b:f1:b9:15:49:12:12:e4:7a:0f:ac:8c:7e:dc:
	<          e8:b3:2b:ad:37:e4:d9:90:34:e0:1d:b8:5e:5c:fb:e2:fa:ed:
	<          a2:11:0c:00:5b:e3:29:c6:51:7d:d6:1b:06:73:56:25:fe:20:
	<          17:28:bb:dd:5c:8e:a6:bc:cf:a2:cf:56:75:f7:f0:cc:e2:c4:
	<          28:57:9b:79:6c:5d:c5:63:0b:a5:47:4d:78:66:5b:0f:36:60:
	<          49:70:44:75:0a:d1:76:52:9a:81:ee:02:13:39:ea:cc:a5:a1:
	<          45:23:02:91:36:03:e3:46:2e:c8:ce:2c:83:1f:73:b8:e4:96:
	<          e3:2b:97:3b
	---
	>          84:a8:9a:11:a7:d8:bd:0b:26:7e:52:24:7b:b2:55:9d:ea:30:
	>          89:51:08:87:6f:a9:ed:10:ea:5b:3e:0b:c7:2d:47:04:4e:dd:
	>          45:37:c7:ca:bc:38:7f:b6:6a:1c:65:42:6a:73:74:2e:5a:97:
	>          85:d0:cc:92:e2:2e:38:89:d9:0d:69:fa:1b:9b:f0:c1:62:32:
	>          65:4f:3d:98:db:da:d6:66:da:2a:56:56:e3:11:33:ec:e0:a5:
	>          15:4c:ea:75:49:f4:5d:ef:15:f5:12:1c:e6:f8:fc:9b:04:21:
	>          4b:cf:63:e7:7c:fc:aa:dc:fa:43:d0:c0:bb:f2:89:ea:91:6d:
	>          cb:85:8e:6a:9f:c8:f9:94:bf:55:3d:42:82:38:4d:08:a4:a7:
	>          0e:d3:65:4d:33:61:90:0d:3f:80:bf:82:3e:11:cb:8f:3f:ce:
	>          79:94:69:1b:f2:da:4b:c8:97:b8:11:43:6d:6a:25:32:b9:b2:
	>          ea:22:62:86:0d:a3:72:7d:4f:ea:57:3c:65:3b:2f:27:73:fc:
	>          7c:16:fb:0d:03:a4:0a:ed:01:ab:a4:23:c6:8d:5f:8a:21:15:
	>          42:92:c0:34:a2:20:85:88:58:98:89:19:b1:1e:20:ed:13:20:
	>          5c:04:55:64:ce:9d:b3:65:fd:f6:8f:5e:99:39:21:15:e2:71:
	>          aa:6a:88:82


Author
------

Adrian Vollmer, 2017-2019

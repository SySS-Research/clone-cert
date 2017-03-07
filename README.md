clone-cert.sh
=============

This is a simple shell script that reads the subject and issuer of an X.509
certificate associated with an SSL wrapped TCP port and uses `openssl` to
create a similar certificate with the same subject and the same issuer. This
is particularly useful if you want to demonstrate why self-signed
certificate cannot provide any security. Of course, the fingerprint of the
cloned certificate will be different... but who checks the fingerprint of a
self-signed certificate by hand?

Example:

    $ ./clone-cert.sh www.example.com:443
    /tmp/www.example.com:443.key
    /tmp/www.example.com:443.cert

The new certificate is in `/tmp/www.example.com:443.cert` and the
corresponding private key is in /tmp/www.example.com:443.key.

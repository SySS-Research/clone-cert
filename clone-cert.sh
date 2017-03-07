#!/bin/bash
# Adrian Vollmer, SySS GmbH 2017

set -e

HOST="$1"
SERVER="$(printf "%s" "$HOST" | cut -f1 -d:)"
DIR="/tmp/"
KEYLENGTH=1024 # 1024 is faster, but less secure than 4096

if [ "$HOST" = "" ] ; then
cat <<EOF
Clone an X509 certificate. The forged certificate and the corresponding key
will be located in $DIR. Their filenames make up the output of this script.

Usage: $0 <host>:<port>
EOF
    exit 1
fi

comma2slash () {
    quotes=0
    while IFS= read -n1 c ; do
        if [ "$c" = "\"" ] ; then
             ((quotes+=1))
        fi
        if [ "$c" = "," ] && ((quotes % 2 == 0 ))  ; then
            IFS= read -r -n1 c2
            if [ "$c$c2" = ", " ] ; then
                printf "%s" "/"
            else
                printf "%s" "$c$c2"
            fi
        else
            printf "%s" "$c"
        fi
    done
}

cleanup () {
    # sed "s/^[^=]\+=/\//" | sed 's/ = /=/g' | comma2slash | sed 's/"//g'
    sed "s/^[^=]\+=\//\//"
}

CERT="$(openssl s_client -servername "$SERVER" \
        -connect "$HOST" < /dev/null 2>  /dev/null)"

SUBJ="$(printf "%s" "$CERT" | grep "^subject" | cleanup )"
ISSUER="$(printf "%s" "$CERT" | grep "^issuer" | cleanup )"
DATES="$(printf "%s" "$CERT" | openssl x509 -noout -dates | sed 's/^.*=/\//')"
ALTNAMES="$(printf "%s" "$CERT" | openssl x509 -noout -text | grep DNS: | sed 's/DNS://g')"


STARTDATE="$(printf "%s" "$DATES" | head -n1 | sed 's/\///g')"
ENDDATE="$(printf "%s" "$DATES" | tail -n1 | sed 's/\///g')"
ENDDATE="$(date --date="$ENDDATE" +"%s")"
NOW=$(date +"%s")
((DAYS=(ENDDATE-NOW)/3600/24))

if [ "$SUBJ" = "$ISSUER" ] ; then #  self-signed
    openssl req -new -newkey rsa:$KEYLENGTH -days $DAYS -nodes -x509 \
        -subj "$SUBJ" -keyout "$DIR$HOST.key" -out "$DIR$HOST.cert" \
        2> /dev/null
else
    openssl req -new -newkey rsa:$KEYLENGTH -nodes -x509 \
        -subj "$ISSUER" -keyout "$DIR$HOST.ca.key" \
        -out "$DIR$HOST.ca.cert" 2> /dev/null
    openssl req -new -newkey rsa:$KEYLENGTH  -nodes \
        -subj "$SUBJ" -keyout "$DIR$HOST.key"  -out "$DIR$HOST.req" \
        2> /dev/null
        # -config <(printf "[req]\nreq_extensions = v3_req\n[ v3_req ]
        # keyUsage = nonRepudiation, digitalSignature, keyEncipherment
        # subjectAltName = @alt_names
        # [alt_names]
        # DNS.1 = server1.example.com")
        # TODO Set alt names
    openssl x509 -CAkey "$DIR$HOST.ca.key" -days "$DAYS" \
        -CA "$DIR$HOST.ca.cert" -req -in "$DIR$HOST.req" \
        -out "$DIR$HOST.cert" -set_serial 0  2> /dev/null
    # TODO how to set notBefore date?
fi

printf "%s\n" "$DIR$HOST.key"
printf "%s\n" "$DIR$HOST.cert"

#!/bin/bash

# Setup
# SWTPM: rm -rf ~/.local/share/tpm2-tss/user/keystore/* && sudo rm -rf /usr/local/var/lib/tpm2-tss/system/keystore/* && sudo chmod a+w,a+r /usr/local/var/lib/tpm2-tss/system/keystore && rm -f tpm2-00.permall && ./src/swtpm/swtpm socket --tpm2 --server port=2321 --ctrl type=tcp,port=2322 --flags not-need-init --tpmstate dir="."
# export TSS2_FAPICONF=~/paper/trusted-update-2/code/fapi-config/fapi-config.json

source ./config.cfg


# --- Output directory --- #

OUT_KEYS=keys
OUT_DATA=data

# --- Functions --- #

function ecu_provision {
    key=$2
    mkdir -p ECU_KEYSTORE
    mkdir -p ECU_DATASTORE
    cat $key > ECU_KEYSTORE/key 
}

function ecu_answerchallenge {

    echo $ECU_PORT

    ncat -l $ECU_PORT | xxd -p -r > ECU_DATASTORE/tpm.nonce

    startOverall=`date +%s%N`

    echo "ECU_DATASTORE/tpm.nonce: "
    cat ECU_DATASTORE/tpm.nonce | xxd -p -c36
    echo ""

    if [[ `cat ECU_KEYSTORE/key` == *"BEGIN"* ]]; then

        echo "PEM Key"

        # NONCE=$(cat ECU_DATASTORE/tpm.nonce | xxd -p -c32)

        # echo "NONCE"
        # echo $NONCE

        # echo key
        # cat ECU_KEYSTORE/key

        if [[ `cat ECU_KEYSTORE/key` == *"RSA"* ]]; then
            echo "RSA"

            { echo -n "`cat ECU_DATASTORE/tpm.nonce | xxd -p -c36 | head -c 64`"; echo -n "0000"; echo -n "00"; echo -n "00"; } | xxd -p -r | sha256sum | head -c 64 > ECU_DATASTORE/ahash.file

            echo "ECU_DATASTORE/ahash.file: "
            cat ECU_DATASTORE/ahash.file 
            echo ""

            xxd -p -r ECU_DATASTORE/ahash.file > ECU_DATASTORE/ahash.bin
            echo ""

            # openssl pkeyutl -sign -in ECU_DATASTORE/ahash.bin -inkey ECU_KEYSTORE/key -out ECU_DATASTORE/sig.ecu \
            #     -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:-1

            # openssl pkeyutl -sign -in ECU_DATASTORE/ahash.bin -inkey ECU_KEYSTORE/key -out ECU_DATASTORE/sig.ecu \
            #     -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:-2

            xxd -p -r ECU_DATASTORE/ahash.file | openssl pkeyutl -sign -inkey ECU_KEYSTORE/key -out ECU_DATASTORE/sig.ecu \
                -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss #-pkeyopt rsa_pss_saltlen:auto

            # openssl dgst -sha256 -sign ECU_KEYSTORE/key -out ECU_DATASTORE/sig.ecu ECU_DATASTORE/ahash.file

            echo "ECU_DATASTORE/sig.ecu: "
            cat ECU_DATASTORE/sig.ecu | xxd -p -c256
            echo ""

            cat ECU_DATASTORE/sig.ecu | xxd -p -c256 | tr -d \\n | ncat $TPM_IP $TPM_PORT

        else
            echo "ECC"

            openssl dgst -sha256 -sign ECU_KEYSTORE/key -out ECU_DATASTORE/sig.ecu ECU_DATASTORE/tpm.nonce

            echo "ECU_DATASTORE/sig.ecu: "
            cat ECU_DATASTORE/sig.ecu | xxd -p -c144
            echo ""
            cat ECU_DATASTORE/sig.ecu | xxd -p -c144 | ncat $TPM_IP $TPM_PORT

        fi

    else

        echo "HMAC Key"

        { echo -n "`cat ECU_DATASTORE/tpm.nonce | xxd -p -c32`"; echo -n "0000"; echo -n "00"; echo -n "00"; } | xxd -p -r | sha256sum | head -c 64 > ECU_DATASTORE/ahash.file

        echo "ECU_DATASTORE/ahash.file: "
        cat ECU_DATASTORE/ahash.file 
        echo ""

        myhexkey=$(cat ECU_KEYSTORE/key | xxd -p | tr -d \\n )

        echo "myhexkey: "
        echo -n $myhexkey
        echo ""

        cat ECU_DATASTORE/ahash.file | xxd -p -r | openssl dgst -sha256 -mac hmac -macopt hexkey:$myhexkey | sed "s/(stdin)= //" | tr -d \\n | xxd -r -p > ECU_DATASTORE/sig.ecu

        echo "ECU_DATASTORE/sig.ecu: "
        cat ECU_DATASTORE/sig.ecu | xxd -p -c32
        echo ""

        cat ECU_DATASTORE/sig.ecu | xxd -p -c32 | ncat $TPM_IP $TPM_PORT

    fi

    endOverall=`date +%s%N`

    echo $endOverall
    echo ""
    echo $startOverall
    echo ""

    echo Overall Execution time was `expr $endOverall - $startOverall` nanoseconds.

    # rm -r ECU_DATASTORE/*
}


function ecu_sendnonce {

    alg=$2
    myhexkey=$3
    # myhexkey=$(echo $myhexkey| xxd -p)

    startOverall=`date +%s%N`

    head -c 32 /dev/urandom | xxd -p -c32 | ncat $TPM_IP $TPM_PORT

    startSend=`date +%s%N`

    ncat -l $ECU_PORT | xxd -p -r > ECU_DATASTORE/tpm.sig

    endSend=`date +%s%N`

    if [[ $alg == rsa ]]; then
        xxd -p -r ECU_DATASTORE/tpm.sig | openssl pkeyutl -sign -inkey ECU_KEYSTORE/key -out ECU_DATASTORE/sig.ecu \
                    -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss #-pkeyopt rsa_pss_saltlen:auto
    fi
    if [[ $alg == ecc ]]; then
        xxd -p -r ECU_DATASTORE/tpm.sig | openssl dgst -sha256 -sign ECU_KEYSTORE/key -out ECU_DATASTORE/sig.ecu
    fi
    if [[ $alg == hmac ]]; then
        echo $myhexkey
        cat ECU_DATASTORE/ahash.file | xxd -p -r | openssl dgst -sha256 -mac hmac -macopt hexkey:$myhexkey | sed "s/(stdin)= //" | tr -d \\n | xxd -r -p > ECU_DATASTORE/sig.ecu
    fi

    endOverall=`date +%s%N`

    echo Overall Execution time was `expr $endOverall - $startOverall` nanoseconds.
    echo Network time was `expr $endSend - $startSend` nanoseconds.
    echo Processing time was `expr $startSend - $startOverall + $endOverall - $endSend` nanoseconds.
}


ecu_help(){
    echo "
    Usage: $(basename $0) [options] <action> <directory> [additional parameters]
    Actions:
        

    Full Example:
        [ 0. bash main_ecu.sh help ]
          1. bash main_ecu.sh provision keys/symkey
          2. bash main_ecu.sh answerchallenge
          3a. bash main_ecu.sh sendnonce rsa
          3b. bash main_ecu.sh sendnonce ecc
          3c. bash main_ecu.sh sendnonce hmac "123456789"
    "
}

# --- Main --- #

ecumain() {


action="$1"

    if [ "$action" = "-h" -o "$action" = "--help" ]; then
        action=help
    fi

    ecu_$action "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8"

    RET=$?
    if [ $RET -ne 0 ]; then
        echo "Error occured..."
        return $RET
    fi
    return 0


}

if [ $# -ne 0 ]; then
    ecumain "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8"
else
    true
fi

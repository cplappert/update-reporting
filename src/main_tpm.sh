#!/bin/bash

# Setup
# SWTPM: rm -rf ~/.local/share/tpm2-tss/user/keystore/* && sudo rm -rf /usr/local/var/lib/tpm2-tss/system/keystore/* && sudo chmod a+w,a+r /usr/local/var/lib/tpm2-tss/system/keystore && rm -f tpm2-00.permall && ./src/swtpm/swtpm socket --tpm2 --server port=2321 --ctrl type=tcp,port=2322 --flags not-need-init --tpmstate dir="."
# export TSS2_FAPICONF=~/paper/trusted-update-2/code/fapi-config/fapi-config.json

source ./config.cfg
TCTI="swtpm:host=10.0.0.20,port=2321" #mssim #device    
KEY_STORE_PATH="/usr/local/var/lib/tpm2-tss/system/keystore/"

# --- Variables --- #

PATH_POL_AUTHORIZE="/policy/pol_authorize"
PATH_POL_TMP="/policy/pol_tmp"
# PATH_REVOCATION="/nv/Owner/rev_ctr"
# PATH_BITMASK="/nv/Owner/nv_report"

PATH_POL_EAP="/policy/pol_eap"
PATH_POL_READ="/policy/pol_bit_read"

# PATH_POL_AUTHORIZED="/policy/pol_authorized"

# PATH_POL_KSP="/policy/pol_ksp"

# PATH_POLICY_JSON="eap.json"


# PATH_REPORT_KEY="HS/SRK/reportKey"


LOG_FILE="log.txt"
# OUTPUT_FILE="nonce.file"
# SIGNATURE_FILE="sig.file"


# --- Output directory --- #

OUT_KEYS=keys
OUT_DATA=data

# --- Functions --- #


function cleanup {
    echo cleanup
    tss2_delete --path $PATH_POL_AUTHORIZE
    tss2_delete --path $PATH_POL_AUTHORIZED

    rm $LOG_FILE


    tss2_delete --path $PATH_REVOCATION
    tss2_delete --path $PATH_BITMASK
    tss2_delete --path $PATH_POL_KSP
    tss2_delete --path $PATH_REPORT_KEY
    # rm $OUTPUT_FILE
    # rm $SIGNATURE_FILE
}

# trap cleanup EXIT

function getJsonValueFromKey {
    key=$1
    position=$2
    awk -F"[,:}]" '{for(i=1;i<=NF;i++){if($i~/'$key'\042/){print $(i+1)}}}' | tr -d '"' | sed -n ${position}p
}


function tpm_createbackendkeys {
    mkdir -p $2
    key_dir=$2
    alg=$3
    symkey=$4

    printf $symkey > $key_dir/symkey

    case "$alg" in
        "ecc")
            echo "ECC"
            openssl ecparam -name secp256r1 -genkey -noout -out $key_dir/backend_priv.pem
            openssl ec -in $key_dir/backend_priv.pem -pubout -out $key_dir/backend_pub.pem
            cp $key_dir/backend_priv.pem $key_dir/ecu_priv.pem
            cp $key_dir/backend_pub.pem $key_dir/ecu_pub.pem
            printf "ecc" > $key_dir/alg
            sed -i 's/P_RSA2048SHA256/P_ECCP256SHA256/' fapi-config/fapi-config.json 
            ;;
        "rsa")
            echo "RSA"
            openssl genrsa -out $key_dir/backend_priv.pem 2048
            openssl rsa -in $key_dir/backend_priv.pem -pubout -out $key_dir/backend_pub.pem
            cp $key_dir/backend_priv.pem $key_dir/ecu_priv.pem
            cp $key_dir/backend_pub.pem $key_dir/ecu_pub.pem
            printf "rsa" > $key_dir/alg
            sed -i 's/P_ECCP256SHA256/P_RSA2048SHA256/' fapi-config/fapi-config.json 
            ;;
        *)
            echo "ERROR: SPECIFY ALG"
            exit 1
            ;;
    esac
}

# bash main_tpm.sh provision keys/backend_pub.pem HS/SRK/attestkey HS/SRK/symkey keys/symkey /nv/Owner/rev_ctr /nv/Owner/nv_report 1
function tpm_provision {
    backend_pub_pem=$2
    path_key_attest=$3
    path_key_seal=$4
    path_input_seal=$5
    path_revocation=$6
    path_nv_report=$7
    bitmap=$8

    tss2 createnv --path $path_revocation --type=counter --authValue ""

    tss2 nvincrement --nvPath $path_revocation

POLICY_AUTHORIZE=$(cat <<EOF
{
    "description":"Initial Authorization Policy",
    "policy":[
        {
            "type": "POLICYAUTHORIZE",
            "policyRef": [ 1, 2, 3, 4, 5 ],
            "keyPEM": "`cat $backend_pub_pem`",
        }
    ]
}
EOF
)

    echo -e "$POLICY_AUTHORIZE" | tss2_import --path $PATH_POL_AUTHORIZE --importData -

    tss2 createnv --path $path_nv_report --type "bitfield" --size 64 --policyPath $PATH_POL_AUTHORIZE --authValue ""

    tss2 delete --path $PATH_POL_AUTHORIZE


POLICY_KSP=$(cat <<EOF 
{
    "description":"Key Sealing Policy",
    "policy":[
        {
          "type": "NV",
          "nvPath": "`printf "$path_nv_report"`",
          "operandB": "`printf "$bitmap"`",
          "operation": "eq"
        },
    ]
}
EOF
)

    echo -e "$POLICY_KSP" | tss2_import --path $PATH_POL_TMP --importData -

    # tss2 createkey --path $path_key_attest --policyPath $PATH_POL_TMP --type="sign, noda" --authValue ""
    tss2 createkey --path $path_key_attest --type="sign, noda" --authValue ""

    tss2 exportkey --pathOfKeyToDuplicate=$path_key_attest --exportedData=exportedData.file
    cat exportedData.file | jq '.pem_ext_public' --raw-output > keys/tpm_pub.pem

    cat $path_input_seal | tr -d \\n | tss2 createseal --path $path_key_seal --type="noDa" --authValue="" --data -

    tss2 delete --path $PATH_POL_TMP

}

function getFapiHandle {
    path=$1
    handle=`cat $path | getJsonValueFromKey "nvIndex" 1`
    handle=$(printf '0x%x\n' $handle)
    echo $handle
}

# 4a. bash main_tpm.sh createeappolicy keys/backend_pub.pem keys/ecu_pub.pem /nv/Owner/rev_ctr /nv/Owner/nv_report 1 data
# 4b. bash main_tpm.sh createeappolicy keys/backend_pub.pem HS/SRK/symkey /nv/Owner/rev_ctr /nv/Owner/nv_report 1 data

function tpm_createeappolicy {
    backend_pub=$2
    ecu_key=$3
    path_revocation=$4
    path_bitmask=$5
    bitmap=$6
    out_file=$7

    tss2 delete --path $PATH_POL_EAP > /dev/null 2>&1 && true 

    # echo BITMAP: $bitmap
    mkdir -p data

    handle=$(getFapiHandle $KEY_STORE_PATH$path_bitmask/object.json)

    tpm2_nvsetbits -T $TCTI $handle -i $bitmap --cphash data/hash_tmp 

    CPHASH=$(cat data/hash_tmp | xxd -p -c 32 -s 2)
    rm data/hash_tmp 

    if [[ $ecu_key == *".pem"* ]]; then
        IFS= # <- IMPORTANT
        JSON_ENTRY="\"keyPEM\": \"`cat $ecu_key`\","
        # KEY=`cat $ecu_key`
    else
        IFS= # <- IMPORTANT
        JSON_ENTRY="\"keyPath\": \"`printf $ecu_key`\","
        # KEY=`printf $ecu_key`
    fi


# "keyPEM": "`cat "$ecu_key"`",
POLICY_EAP=$(cat <<EOF 
{
    "description":"ECU Authorization Policy",
    "policy":[
        {
            "type": "POLICYCPHASH",
            "cpHash": "`printf "$CPHASH"`",
        },
        {
            "type": "POLICYSIGNED",
            `echo -e $JSON_ENTRY`
            "keyPEMhashAlg": "SHA256"
        },
        {
          "type": "NV",
          "nvPath": "`printf "$path_revocation"`",
          "operandB": "1000000000000005",
          "operation": "signed_le"
        },
    ]
}
EOF
)

    echo -e "$POLICY_EAP"

    echo -e "$POLICY_EAP" > "$out_file/eap_template.policy"

    echo -e "$POLICY_EAP" | tss2 import --path $PATH_POL_EAP --importData -
    tss2 createkey --path HS/SRK/tmpkey --policyPath $PATH_POL_EAP --type="sign, noda" --authValue ""
    Policy_Out=$(tss2 exportpolicy --path HS/SRK/tmpkey --jsonPolicy - )
    tss2 delete --path HS/SRK/tmpkey
    # tss2 delete --path $PATH_POL_EAP

    echo -e "$Policy_Out" > "$out_file/eap_inst.policy"

    # echo $KEY

    AUTHORIZED_POLICY=$(authorizePolicy "$Policy_Out" "`cat $backend_pub`")
    # AUTHORIZED_POLICY=$(authorizePolicy "$Policy_Out" "`echo -e $KEY`")

    echo -e "$AUTHORIZED_POLICY" > "$out_file/eap_authorized.policy"

}

function tpm_createreadpolicy {

backend_pub=$2
out_file=$3

POL_READ=$(cat <<EOF 
{
    "description":"Bitmap Read Policy",
    "policy":[
        {
            "type":"POLICYPCR",
            "pcrs":[
                {
                    "pcr":16,
                    "hashAlg":"TPM2_ALG_SHA256",
                    "digest":"00000000000000000000000000000000000000000000000000000000000000000"
                }
            ]
        }
    ]
}
EOF
)

    echo -e "$POL_READ" | tss2 import --path $PATH_POL_READ --importData -
    tss2 createkey --path HS/SRK/tmpkey --policyPath $PATH_POL_READ --type="sign, noda" --authValue ""
    Policy_Out=$(tss2 exportpolicy --path HS/SRK/tmpkey --jsonPolicy - )
    tss2 delete --path HS/SRK/tmpkey
    tss2 delete --path $PATH_POL_READ

    AUTHORIZED_POLICY=$(authorizePolicy "$Policy_Out" "`cat $backend_pub`")

    # echo -e "$AUTHORIZED_POLICY" | tss2 import --path $PATH_POL_READ --importData -

    echo -e "$AUTHORIZED_POLICY" > "$out_file/read_authorized.policy"

}

# 5a. bash main_tpm.sh authorizewrite data/eap_authorized.policy /nv/Owner/nv_report keys/ecu_priv.pem 1
# 5b. bash main_tpm.sh authorizewrite data/eap_authorized.policy /nv/Owner/nv_report keys/symkey 1
function tpm_authorizewrite {

    START_FILE=start.file
    END_FILE=end.file

    startOverall=`date +%s%N`

    policy_path=$2
    path_nv_report=$3
    path_sign_key=$4
    bitmap=$5

    cat $policy_path | tss2 import --path $PATH_POL_TMP --importData -

    # rm -f data/tpm.nonce

if [[ $path_sign_key == *".pem"* ]]; then

echo "PEM Key"

# expect <<EOF
#     spawn sh -c "tss2 nvsetbits --nvPath $path_nv_report --bitmap $bitmap 2> $LOG_FILE"
#     expect "Filename for nonce output: " {
#         send "data/tpm.nonce\r"
#         puts [open "$START_FILE" w] $expect_out `date +%s%N`
#         expect "Filename for signature input: " {
#             exec cat data/tpm.nonce | xxd -p -c36 | head -c 64 | ncat $ECU_IP $ECU_PORT
#             exec ncat -l $TPM_PORT | xxd -p -r > data/ecu.sig
#             puts [open $END_FILE w] $expect_out `date +%s%N`
#             send "data/ecu.sig\r"
#             exp_continue
#         }
#     }
# EOF

expect <<EOF
    spawn sh -c "tss2 nvsetbits --nvPath $path_nv_report --bitmap $bitmap 2> $LOG_FILE"
    expect "Filename for nonce output: " {
        send "data/tpm.nonce\r"
        puts [open "$START_FILE" w] $expect_out `date +%s%N`
        expect "Filename for signature input: " {
            exec cat data/tpm.nonce | xxd -p -c36 | ncat $ECU_IP $ECU_PORT
            exec ncat -l $TPM_PORT | xxd -p -r > data/ecu.sig
            puts [open $END_FILE w] $expect_out `date +%s%N`
            send "data/ecu.sig\r"
            exp_continue
        }
    }
EOF

else

echo "HMAC Key"

expect <<EOF
    spawn sh -c "tss2 nvsetbits --nvPath $path_nv_report --bitmap $bitmap 2> $LOG_FILE"
    expect "Filename for nonce output: " {
        send "data/tpm.nonce\r"
        puts [open "$START_FILE" w] $expect_out `date +%s%N`
        expect "Filename for signature input: " {
            exec cat data/tpm.nonce | xxd -p -c36 | head -c 64 | ncat $ECU_IP $ECU_PORT
            exec ncat -l $TPM_PORT | xxd -p -r > data/ecu.sig
            puts [open $END_FILE w] $expect_out `date +%s%N`
            send "data/ecu.sig\r"
            exp_continue
        }
    }
EOF

fi

    endOverall=`date +%s%N`

    tss2 delete --path $PATH_POL_TMP

    startTrans=`cat $START_FILE`
    endTrans=`cat $END_FILE`

    echo Transmission time was `expr $endTrans - $startTrans` nanoseconds.
    echo Overall Execution time was `expr $endOverall - $startOverall` nanoseconds.
}

# 6.  bash main_tpm.sh readnvreport data/read_authorized.policy /nv/Owner/nv_report
function tpm_readnvreport {
    policy_path=$2
    path_nv_report=$3

    cat $policy_path | tss2 import --path $PATH_POL_READ --importData -

    tss2 nvread --nvPath $path_nv_report --data - | xxd

    tss2 delete --path $PATH_POL_READ

}

# 7.  bash main_tpm.sh zeronvreport data/read_authorized.policy /nv/Owner/nv_report
function tpm_zeronvreport {
    policy_path=$2
    path_nv_report=$3

    tss2 delete --path $path_nv_report

    cat $policy_path | tss2_import --path $PATH_POL_AUTHORIZE --importData -

    tss2 createnv --path $path_nv_report --type "bitfield" --size 64 --policyPath $PATH_POL_AUTHORIZE --authValue ""

    tss2 delete --path $PATH_POL_AUTHORIZE
}

function tpm_answerchallenge {

    key_path=$2
    path_nv_report=$3
    bitmap=$4
    alg=$5
    input=$6

    ncat -l $TPM_PORT | xxd -p -r > data/ecu.nonce

    startOverall=`date +%s%N` 

    if [[ $alg == rsa ]]; then

        tss2 sign --keyPath $key_path --padding="RSA_PSS" --digest data/ecu.nonce --signature=signature.file -f

    fi
    if [[ $alg == ecc ]]; then
        tss2 sign --keyPath $key_path --digest data/ecu.nonce --signature=signature.file -f
    fi
    if [[ $alg == hmac ]]; then
        myhexkey=$(tss2_unseal --path $key_path --data=- | xxd -p | xxd -p -r)
        echo myhexkey
        echo $myhexkey

        cat data/ecu.nonce | xxd -p -c32 | openssl dgst -sha256 -mac hmac -macopt hexkey:$myhexkey  | sed "s/(stdin)= //" | tr -d \\n | xxd -r -p > signature.file
    fi

    size=$(cat signature.file | wc -c)

    cat signature.file | xxd -p -c$size | ncat $ECU_IP $ECU_PORT

    endOverall=`date +%s%N`

    echo Overall Execution time was `expr $endOverall - $startOverall` nanoseconds.

}

function authorizePolicy {
    to_be_signed=$1
    backend_pub=$2

    policy_digest=`echo -e "$to_be_signed" | getJsonValueFromKey "digest" 1` 

    policy_digest="$policy_digest""0102030405"

    signature_eap=$(echo -n $policy_digest | \
        xxd -r -p | openssl dgst -sha256 -sign $OUT_KEYS/backend_priv.pem -hex | \
        sed 's/^.* //')

POLICY_AUTH_TEMPLATE_EAP=$(cat <<EOF
    "policyAuthorizations":[
        {
            "type": "pem",
            "policyRef": [ 1, 2, 3, 4, 5 ],
            "key": "`echo -e "$backend_pub"`",
            "signature": "`echo -e "$signature_eap"`"
        }
    ],
EOF
)
    search_string="\"policy\":["

    echo -e "${to_be_signed/$search_string/$POLICY_AUTH_TEMPLATE_EAP $search_string}"
}

tpm_help(){
    echo "
    Usage: $(basename $0) [options] <action> <directory> [additional parameters]
    Actions:
        createbackendkeys       Create ECC key pair
        # createderivationsecret  Create derivation secret
        # createupdate            Create Update Binary
        # signupdate              Sign update

    Full Example:
        [ 0. bash main_tpm.sh help ]
          1a. bash main_tpm.sh createbackendkeys keys rsa "123456789"
          1b. bash main_tpm.sh createbackendkeys keys ecc "123456789"
          2.  bash main_tpm.sh provision keys/backend_pub.pem HS/SRK/attestkey HS/SRK/symkey keys/symkey /nv/Owner/rev_ctr /nv/Owner/nv_report 1
          3.  bash main_tpm.sh createreadpolicy keys/backend_pub.pem data
          4a. bash main_tpm.sh createeappolicy keys/backend_pub.pem keys/ecu_pub.pem /nv/Owner/rev_ctr /nv/Owner/nv_report 1 data
          4b. bash main_tpm.sh createeappolicy keys/backend_pub.pem HS/SRK/symkey /nv/Owner/rev_ctr /nv/Owner/nv_report 1 data
          5a. bash main_tpm.sh authorizewrite data/eap_authorized.policy /nv/Owner/nv_report keys/ecu_priv.pem 1
          5b. bash main_tpm.sh authorizewrite data/eap_authorized.policy /nv/Owner/nv_report keys/symkey 1
          6.  bash main_tpm.sh readnvreport data/read_authorized.policy /nv/Owner/nv_report
          7.  bash main_tpm.sh zeronvreport data/read_authorized.policy /nv/Owner/nv_report
          8a.  bash main_tpm.sh answerchallenge HS/SRK/attestkey /nv/Owner/nv_report 1 rsa
          8b.  bash main_tpm.sh answerchallenge HS/SRK/attestkey /nv/Owner/nv_report 1 ecc
          8c.  bash main_tpm.sh answerchallenge HS/SRK/attestkey /nv/Owner/nv_report 1 hmac "123456789"
    "
}

# --- Main --- #

tpmmain() {


action="$1"

    if [ "$action" = "-h" -o "$action" = "--help" ]; then
        action=help
    fi

    tpm_$action "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8"

    RET=$?
    if [ $RET -ne 0 ]; then
        echo "Error occured..."
        return $RET
    fi
    return 0


}

if [ $# -ne 0 ]; then
    tpmmain "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8"
else
    true
fi
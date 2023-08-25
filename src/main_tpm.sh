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

    tss2 createkey --path $path_key_attest --policyPath $PATH_POL_TMP --type="sign, noda" --authValue ""

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



    tss2 delete --path $key_path

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
    tss2 delete --path $path_nv_report

    cat data/read_authorized.policy | tss2 import --path $PATH_POL_READ --importData -

    tss2 createnv --path $path_nv_report --type "bitfield" --size 64 --policyPath $PATH_POL_READ --authValue ""

    tss2 nvsetbits --nvPath $path_nv_report --bitmap $bitmap

    echo -e "$POLICY_KSP"


    echo -e "$POLICY_KSP" | tss2 import --path $PATH_POL_TMP --importData -

    if [[ $alg != hmac ]]; then
        tss2 createkey --path $key_path --type="sign, noda" --policyPath $PATH_POL_TMP --authValue ""
    else
        echo -n $input | tr -d \\n | tss2 createseal --path $key_path --type="noDa" --authValue="" --data -
    fi

    ncat -l $TPM_PORT | xxd -p -r > data/ecu.nonce

    startOverall=`date +%s%N` 

    if [[ $alg == rsa ]]; then

        tss2 sign --keyPath $key_path --padding="RSA_PSS" --digest data/ecu.nonce --signature=signature.file -f

    fi
    if [[ $alg == ecc ]]; then
        tss2 sign --keyPath $key_path --digest data/ecu.nonce --signature=signature.file -f
    fi
    if [[ $alg == hmac ]]; then
        myhexkey=$(tss2_unseal --path $key_path --data=- | xxd -p)
        echo myhexkey
        echo $myhexkey

        cat data/ecu.nonce | xxd -p -r | openssl dgst -sha256 -mac hmac -macopt hexkey:$myhexkey  | sed "s/(stdin)= //" | tr -d \\n | xxd -r -p > signature.file
    fi

    size=$(cat signature.file | wc -c)

    cat signature.file | xxd -p -c$size | ncat $ECU_IP $ECU_PORT

    endOverall=`date +%s%N`

    echo Overall Execution time was `expr $endOverall - $startOverall` nanoseconds.

    tss2 delete --path $PATH_POL_TMP
    tss2 delete --path $PATH_POL_READ
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


# tpm2_startup -Tswtpm -c

# if [ "$PROVISION" = "True" ]; then

#     ####################### Create NV ##################################

#     # tss2 createnv --path $PATH_REVOCATION --type=counter --authValue ""
#     # tss2 nvincrement --nvPath $PATH_REVOCATION
#     # abc=$(tss2_nvread --nvPath $PATH_REVOCATION --data - | xxd)
#     # echo REVOCATION COUNTER
#     # echo $abc


#     ####################### Create IAP ##################################

# POLICY_AUTHORIZE=$(cat <<EOF
# {
#     "description":"Initial Authorization Policy",
#     "policy":[
#         {
#             "type": "POLICYAUTHORIZE",
#             "policyRef": [ 1, 2, 3, 4, 5 ],
#             "keyPEM": "`cat $OUT_KEYS/backend_pub.pem`",
#         }
#     ]
# }
# EOF
# )

#     echo -e "$POLICY_AUTHORIZE" | tss2_import --path $PATH_POL_AUTHORIZE --importData -

#     tss2 createnv --path $PATH_BITMASK --type "bitfield" --size 64 --policyPath $PATH_POL_AUTHORIZE --authValue ""

#     handle=$(getFapiHandle $KEY_STORE_PATH$PATH_BITMASK/object.json)

#     # echo HANDLE
#     # echo $handle

#     tpm2_nvsetbits -T $TCTI $handle -i $BITMAP --cphash $CP_HASH_FILE 


#     CPHASH=$(cat $CP_HASH_FILE | xxd -p -c 32 -s 2)
#     rm $CP_HASH_FILE

#     # tss2 delete --path $PATH_BITMASK


#     ####################### Create EAP ##################################


#     POLICY=$(createEAPPolicy "$CPHASH" "`cat $OUT_KEYS/backend_pub.pem`" "$PATH_REVOCATION")
#     # POLICY=$(createTestPolicy "$CPHASH" "`cat $OUT_KEYS/backend_pub.pem`" "$PATH_REVOCATION")

#     echo POLICY
#     echo -e "$POLICY"

#     ####################### Authorize Policy ##################################

#     AUTHORIZED_POLICY=$(authorizePolicy "$POLICY" "`cat $OUT_KEYS/backend_pub.pem`")

#     echo AUTHORIZED_POLICY
#     echo -e "$AUTHORIZED_POLICY" > $PATH_POLICY_JSON


#     ####################### TEST Reporting Key ##################################
#     ####################### Create Reporting Key ##################################

#     POLICY=$(createKSPPolicy "$PATH_BITMASK" "0")

#     echo -e $POLICY | tss2 import --path $PATH_POL_KSP --importData -

#     tss2_createkey --path=$PATH_REPORT_KEY --type="noDa, sign" --authValue="" #--policyPath=$PATH_POL_KSP

#     touch signature.file

    # echo "INTERRUPT"
    # exit 0

    # netcat -ul -w 0 -p5500 > out.file

#     startTPM=`date +%s%N`
    
#     echo -n "abdefghijklmnopqabdefghijklmnopq" | tss2_sign --keyPath=$PATH_REPORT_KEY --digest=- --signature=signature.file -f

#     endTPM=`date +%s%N`

#     `cat $SIGNATURE_FILE | nc -u -w0 192.168.178.37 3500`

#     rm signature.file


#     echo TPM Execution time was `expr $endTPM - $startTPM` nanoseconds.

#     ###################### /TEST Reporting Key ##################################

#     exit 0


# fi


####################### Load Policy and Access Key ##################################


# startOverall=`date +%s%N`

# cat $PATH_POLICY_JSON | tss2 import --path $PATH_POL_AUTHORIZED --importData -
# #echo -e "$AUTHORIZED_POLICY" | tss2 import --path $PATH_POL_AUTHORIZED --importData -


# # tss2_nvsetbits --nvPath $PATH_BITMASK --bitmap=$BITMAP

# START_FILE=start.file
# END_FILE=end.file

# expect <<EOF
#     spawn sh -c "tss2_nvsetbits --nvPath $PATH_BITMASK --bitmap=$BITMAP 2> $LOG_FILE"
#     expect "Filename for nonce output: " {
#         send "$OUTPUT_FILE\r"
#         puts [open "$START_FILE" w] $expect_out `date +%s%N`
#         expect "Filename for signature input: " {
#             `cat $OUTPUT_FILE | nc -u -w0 192.168.178.37 3500`
#             `netcat -ul -w 0 -p5500 > $SIGNATURE_FILE`
#             puts [open $END_FILE w] $expect_out `date +%s%N`
#             send "$SIGNATURE_FILE\r"
#             exp_continue
#         }
#     }
# EOF

# endOverall=`date +%s%N`

# startTrans=`cat $START_FILE`
# endTrans=`cat $END_FILE`



# echo Transmission time was `expr $endTrans - $startTrans` nanoseconds.
# echo Overall Execution time was `expr $endOverall - $startOverall` nanoseconds.


# expect <<EOF
#     spawn sh -c "tss2_nvsetbits --nvPath $PATH_BITMASK --bitmap=$BITMAP 2> $LOG_FILE"
#     expect "Filename for nonce output: " {
#         send "$OUTPUT_FILE\r"
#         expect "Filename for signature input: " {
#             exec openssl dgst -sha256 -sign $OUT_KEYS/backend_priv.pem -out $SIGNATURE_FILE $OUTPUT_FILE
#             send "$SIGNATURE_FILE\r"
#             exp_continue
#         }
#     }
# EOF


# if grep "ERROR" $LOG_FILE > /dev/null
# then
#   cat $LOG_FILE
#   exit 1
# fi

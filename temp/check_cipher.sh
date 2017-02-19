#!/usr/bin/env bash

#BUGGIEST!!! 
#doesnt work with certain salts!!
#with local salt=A68D6E406A087F05 ok 
# but with local salt=D68D6E406A087F05 wrong???

check() {
    local temp= fd= con=
    local algo=sha256
    local key_size=64
    local iv_size=32
    local pass="MYPASSWORD"
    #works in hexadecimal
    local osalt=A68D6E406A087F05

    hexstring_to_bytes() {
        local hex=$1
        local res=

        for (( i = 0; i < ${#hex}; i+=2 )); do
             res+=$(printf "\x${hex:$i:2}")
        done

        echo $res
    } 

    bytes_to_hexstring() {
        local bytes=$1
        local res=

        for (( i = 1; i < ${#bytes}; i+=3 )); do
             res+=$(printf "${bytes:$i:2}")
        done

        echo $res
    } 



    hasher() {
        local data=$1
        local md=$(echo -nE $data | ${algo}sum)
        local res="${md%%[[:space:]]*}"
        echo -nE ${res^^}
    }


    salt=$(hexstring_to_bytes $osalt)

    fd=$temp
    while (( ${#fd} < $key_size + $iv_size ))
    do
        con=$(hexstring_to_bytes $temp)$pass$salt
        temp=$(hasher "$con")
        # echo temp:$temp
        # echo con :$con
        fd+=$temp
    done

    echo salt:$osalt
    echo key=${fd:0:$key_size}
    echo iv=${fd:$key_size:$iv_size}

    #now with openssl
    echo "now with openssl"
    openssl aes-256-cbc -P -pass pass:$pass  -S $osalt  -md $algo
}

check "$@"


#!/usr/bin/env bash
#Vault safely a file/directory with your openssh private/public keys

#Based on https://gist.github.com/colinstein/de1755d2d7fbe27a0f1e 
# and https://gist.github.com/colinstein/51d686c8f877294e5ab1

#Encrypt
#1. Execute dir/prepare_vault.sh -e if exists
#2. Make a random $key_length password
#3. Encrypt the random password with your rsa public key
#4. Use that random password to encrypt a file/dir (using aes-256-cbc by default)
#5. HMAC your file/dir with the random password
#6. Pack everything to tgz
#Decrypt
#1. Unpack the tgz
#2. Decrypt the random $key_length password with your rsa private key (assume strong passphrase)
#3. Check the saved HMAC for your file/dir with the saved random password
#4. Use the saved random password to decrypt the file/dir with the same parameters as to encrypt
#5. Clean keyfiles
#6. Execute dir/prepare_vault.sh -d if exists
#Generate
#1. Generate the private/public/pkcs8 keys needed to encrypt/decrypt with rsa 4096 :)
#2. You must use a really strong passphrase!

#set_keys_profile
# Change the default "profile", so you can have keys for github, backups, servers,...

#TODO
#1-Unpack to an ecryptfs container

# fail when any side of the pipe fail
set -o pipefail


##########
#  MAIN  #
##########

do_vault() {
    #default profile name
    local actual_profile=vault_$USER
    #default private/public and pkcs8 profile. Use ./$0 -p profilename to change it
    local private_key=~/.ssh/$actual_profile.pem
    local public_key=${private_key%.pem}.pub
    local pkcs8_key=$public_key.pkcs8
    #file/dir to vault
    local vault_file=
    #File name for your files inside the tgz
    local vault_file_enc=files.enc
    local vault_file_enc_hmac=/dev/shm/files.hmac
    #File name for your random password decrypted. Drop it in /dev/shm for security messures
    local keyfile=/dev/shm/secret_key
    #File name for your random password encrypted
    local keyfile_enc=$keyfile.enc
    #default resulting tgz
    local tgz=vault.enc.tgz
    #operation to do
    local cmd=usage
    #algo for PBKDF (not possible to set the iteration count for now :( )
    #WIP from https://github.com/openssl/openssl/pull/2083
    #and singing/verfifying
    local dgst_algo=SHA256
    #Simmetric algorithm
    local sym_algo=aes-256-cbc
    #rsa bits
    local module=4096
    #maximum msg for rsa bits must be length module - 11 bytes
    local key_length=$(($module / 8 - 12))
    #"Metadata" files
    local metadata=/dev/shm/file.esp
    local metadata_enc=$metadata.enc

    ###################
    #  GENERAL ERROR  #
    ###################
    
    general_err() {
        echo "ERROR!:$@"
        exit 1
    }

    ###################
    #  GENERATE KEYS  #
    ###################
    
    generate(){ 
        local count=1

        err() {
            shred -uzf "$private_key" "$public_key" "$pkcs8_key"
            general_err "$@"
        }

        if [[ -f $private_key ]]; then
            read -p "$private_key already exists. Do you want to overwrite it (Yy/Nn)? " -n 1 -r
            echo "" #move to newline
            [[ $REPLY =~ ^[Yy]$ ]] || general_err "$private_key exists. Exit!"
            shred -uzf "$private_key" "$public_key" "$pkcs8_key"
        fi

        echo "$((count++)).Generating $private_key. Type a really strong passphrase!"
        if ! openssl genpkey -algorithm RSA -$sym_algo -outform PEM -out "$private_key" -pkeyopt rsa_keygen_bits:$module ; then
            err "$private_key couldn't be generated. Exit!"
        fi
        chmod 0400 "$private_key"

        echo "$((count++)).Generating $public_key"
        if ! ssh-keygen -y -f "$private_key" > "$public_key"; then
            err "$public_key couldn't be generated. Exit!"
        fi
        #Append the profile in the end of $public_key 
        echo "$(cat $public_key) $actual_profile" > $public_key 
        chmod 0400 "$public_key"

        echo "$((count++)).Generating $pkcs8_key"
        if ! ssh-keygen -e -f "$public_key" -m PKCS8 > "$pkcs8_key"; then
            err "$pkcs8_key couldn't be generated. Exit!"
        fi
        chmod 0400 "$pkcs8_key"

        echo "Done. Keys for profile:\"$actual_profile\" generated!"
        echo "To login with ssh:"
        echo "ssh-copy-id -f -i $public_key remote-machine"
    }

    #############
    #  DECRYPT  #
    #############
    
    decrypt() { 
        local lpass_file=/dev/shm/lpass.file
        local -a metadata_info=()
        local count=1
        local lpass=
        local hmac=
        local salt=

        err() {
            unset -v lpass
            shred -uzf "$metadata" "$metadata_enc" "$lpass_file"
            shred -uzf $keyfile $keyfile_enc  
            shred -uzf "$vault_file_enc" $vault_file_enc_hmac
            general_err "$@"
        }

        [[ -f $private_key ]] ||  err "$private_key not found. Use $0 -p $actual_profile -g to generate one. Exit!"
        [[ -f $tgz ]] || err "$tgz not found. Exit!"

        echo "Decrypting $tgz" for profile: $actual_profile
        echo "============================================"


        if ! tar Pzxf "$tgz"; then
             err "$tgz couldn't be unpacked. Exit!"; 
        fi


        #Ask for the pass phrase and insert it to $lpass_file to not have to enter it twice
        read -s -p "Enter pass phrase for $private_key:" lpass
        echo ""
        if ! ( install -m 0600 /dev/null $lpass_file && echo "$lpass" > $lpass_file ); then
             err "$lpass_file couldn't be generated. Exit!" 
        fi
        unset -v lpass

        #Enter your pass phrase
        echo "$((count++)).Decrypting unique $keyfile_enc"
        if ! openssl pkeyutl -decrypt  -inkey "$private_key" -in $keyfile_enc -out $keyfile -passin file:$lpass_file; then
             err "$keyfile_enc couldn't be decrypted. Exit!" 
        fi

        #Enter your pass phrase
        echo "$((count++)).Decrypting metadata file $metadata_enc"
        if ! openssl pkeyutl -decrypt -inkey "$private_key" -in $metadata_enc -out $metadata -passin file:$lpass_file; then
             err "$metadata_enc couldn't be decrypted. Exit!" 
        fi

        # set metadata info 
        # ${metadata_info[4]} is stuffed randomness
        mapfile -t metadata_info <$metadata
        vault_file=${metadata_info[0]}
        module=${metadata_info[1]}
        key_length=$(($module / 8 - 12))
        sym_algo=${metadata_info[2]}
        dgst_algo=${metadata_info[3]}
 
        #Delete them right now so!
        shred -uzf "$metadata" "$metadata_enc" "$lpass_file"

        #check HMAC with $keyfile for $vault_file_enc before trying to decrypt it
        echo "$((count++)).Checking HMAC of $vault_file_enc with $keyfile"
        if ! hmac=$(openssl dgst -sha256 -hmac file:$keyfile $vault_file_enc); then
            err "$vault_file_enc couldn't be HMAC with $keyfile. Exit!"
        fi

        #compare generated with saved one
        if [[ $hmac != $(<$vault_file_enc_hmac) ]] ; then
            err "HMAC for $vault_file_enc failed for $keyfile. Exit!"
        fi

        #get salt (fast)
        if ! salt=$(openssl $sym_algo -d -P -in "$vault_file_enc" -pass pass:nothing | grep salt); then
             err "$vault_file_enc couldn't be inspected. Exit!" 
        fi

        echo "$((count++)).Decrypting $vault_file_enc with $sym_algo KDF $dgst_algo and $salt"
        if ! openssl $sym_algo -md $dgst_algo -pbkdf2 -iter 1000000 -d -in "$vault_file_enc" -pass file:$keyfile | tar xvz; then
             err "$vault_file_enc couldn't be decrypted. Exit!" 
        fi

        echo "$((count++)).Cleanning up files"
        shred -uzf $keyfile $keyfile_enc 
        shred -uzf "$vault_file_enc" $vault_file_enc_hmac

        echo "Done. $tgz decrypted into $vault_file!" 

        if [[ -x $vault_file/prepare_vault.sh ]]; then
            read -p "Do you want to execute $vault_file/prepare_vault.sh (Yy/Nn)? " -n 1 -r
            echo "" #move to newline
            [[ $REPLY =~ ^[Yy]$ ]] && $vault_file/prepare_vault.sh -d
        fi
    }

    #############
    #  ENCRYPT  #
    #############
    
    encrypt() {
        local count=1
        local temp=
        #package file/dir without absolute path using tar -C $dir $dest
        local dir=${vault_file%/*}
        local dest=${vault_file##*/}
        [[ $dir == $dest ]] && dir=.

        err() {
            if [[ -e $vault_file ]]; then
                shred -uzf $keyfile $keyfile_enc $vault_file_enc $vault_file_enc_hmac
                shred -uzf  "$metadata" "$metadata_enc"
            fi

            general_err "$@"
        }

        [[ -f $private_key ]] || err "$private_key not found. Use $0 -p $actual_profile -g to generate one. Exit!" 
        [[ -f $public_key ]] || err "$public_key not found. Use $0 -p $actual_profile -g to generate one. Exit!" 
        [[ -e $vault_file ]] ||  err "file or dir:$vault_file not found!" 



        echo "Encrypting $vault_file/" directory for profile: $actual_profile
        echo "============================================================"

        #Execute install before packing
        if [[ -x $vault_file/prepare_vault.sh ]]; then
            read -p "Do you want to execute $vault_file/prepare_vault.sh (Yy/Nn)? " -n 1 -r
            echo "" #move to newline
            [[ $REPLY =~ ^[Yy]$ ]] && $vault_file/prepare_vault.sh -e
        fi

        #Generate public pkcs8 if not already
        if [[ ! -f $pkcs8_key ]]; then
            echo "$((count++)).Generating $pkcs8_key"
            if ! ssh-keygen -e -f "$public_key" -m PKCS8 > "$pkcs8_key"; then
                err "$pkcs8_key couldn't be generated. Exit!"
            fi
            chmod 0400 "$pkcs8_key"
        fi

        #generate an unique key
        echo "$((count++)).Generating unique $keyfile of $key_length bytes"
        if ! openssl rand -out $keyfile $key_length;  then
             err "$keyfile couldn't be generated. Exit!" 
        fi

        #encrypt the keyfile
        echo "$((count++)).Generating $keyfile_enc with rsa $module bits"
        if ! openssl pkeyutl -encrypt -pubin -inkey "$pkcs8_key" -in $keyfile -out $keyfile_enc; then
                err "$keyfile_enc couldn't be generated from $pkcs8_key. Exit!"
        fi

        # check if the metadata file can be created
        # maximum ext4 filename = 255
        # max=255 + 4 + 12 + 9 + 45 = 275 
        local max="$dest$module$sym_algo$dgst_algo"
        max=$((${#max} + 45))
        if (( $max > $key_length )); then
            echo "$metadata_enc more than $key_length bytes"
            err "Try renaming $dest to something $(( $max - $key_length )) characters shorter. Exit!"
        fi
        # create $metadata file 
        echo "$dest"      >  $metadata
        echo "$module"    >> $metadata
        echo "$sym_algo"  >> $metadata
        echo "$dgst_algo" >> $metadata
        #stuff some randomness 
        openssl rand 45   >> $metadata
        #encrypt $metadata file
        echo "$((count++)).Generating metadata file $metadata_enc with rsa $module bits"
        if ! openssl pkeyutl -encrypt -pubin -inkey "$pkcs8_key" -in $metadata -out $metadata_enc; then
                err "$metadata_enc couldn't be generated from $pkcs8_key. Exit!"
        fi

        #encrypt the targzed dir
        echo  "$((count++)).Generating $vault_file_enc with $sym_algo KDF $dgst_algo with $keyfile"
        if ! tar czf - -C "$dir" "$dest" | openssl $sym_algo -md $dgst_algo -pbkdf2 -iter 1000000  -salt -out $vault_file_enc -pass file:$keyfile ; then
                err "$vault_file_enc couldn't be generated. Exit!"
        fi

        #HMAC with $keyfile the just generated $vault_file_enc
        echo "$((count++)).Doing HMAC of $vault_file_enc with $keyfile"
        if ! openssl dgst -sha256 -hmac file:$keyfile -out $vault_file_enc_hmac $vault_file_enc; then
            err "$vault_file_enc couldn't be HMAC with $keyfile. Exit!"
        fi

        #Pack everything with the same name. You can rename it when created at your will
        tgz=$dest.enc.tgz

        #package everything
        echo -n "$((count++)).Packing $keyfile_enc, $metadata_enc, $vault_file_enc"
        echo " and $vault_file_enc_hmac into $tgz"
        tar -czf "$tgz" -P $keyfile_enc $vault_file_enc $vault_file_enc_hmac $metadata_enc 

        echo "$((count++)).Cleanning up files"
        shred -uzf $keyfile $keyfile_enc $vault_file_enc $vault_file_enc_hmac
        shred -uzf  "$metadata" "$metadata_enc"

        #simply rm the source file/dir 
        #\rm -rf "$vault_file" 
        echo "Done. File $tgz generated!"
        echo "You can safely now delete $vault_file using shred -uzf or rm -rf if you wish"
    }

    ###########
    #  USAGE  #
    ###########

    usage() {
    local software=${0##*/}
    local msg=(
        "Usage :  $software [options] [--]"
        " "
        "Options:"
        "  -h|help            Display this message"
        "  -e|encrypt  [ARG]  Encrypt ARG into $tgz" 
        "  -d|decrypt  [ARG]  Decrypt ARG"
        "  -g|generate [ARG]  Generate new keys for ARG"
        "  -p|profile   ARG   Change profile"
        "  -s|sign      ARG   Sign a file with your private key"
        "  -v|verify    ARG   Verify a sign with your public key"
        " "
        "Examples:"
        "1.Generate your keys for the default profile:"
        "  $software -g "
        "2.Generate your github's keys:"
        "  $software -p github -g"
        "3.Encrypt 'my secret dir' with the default profile:"
        "  $software -e \"my secret dir\""
        "4.Decrypt $tgz with backups@lenny's profile"
        "  $software -p backups@lenny -d"
        "5.Decrypt private.tgz with the default profile:"
        "  $software -d private.tgz"
        "6.Sign private.tgz with checksum's profile:"
        "  $software -p checksum -s private.tgz"
        "7.Verify sign of private.tgz with checksum's profile:"
        "  $software -p checksum -v private.tgz"
        )
    printf '%s\n' "${msg[@]}"
    exit 0
    
    }    

    
    ######################
    #  SET PROFILE NAME  #
    ######################

    #Change the default keys profile to work in
    set_keys_profile() {
        local orig=$actual_profile
        #set global value
        actual_profile=$1

        private_key=${private_key/$orig/$actual_profile} 
        public_key=${public_key/$orig/$actual_profile} 
        pkcs8_key=${pkcs8_key/$orig/$actual_profile} 
    }

    ###############
    #  SIGN FILE  #
    ###############

    #Sign a file with your private key
    sign_file() {
        local file=$1

        [[  -e $file ]] || general_err "Couldn't find file: $file!"
        if [[ ! -e $private_key ]]; then
            general_err "Couldn't find private key: $private_key!. Try $0 -p $actual_profile -g to generate one"
        fi

        echo "Signing $file with your private key $private_key"
        openssl dgst -$dgst_algo -sign $private_key "$file" > "$file.sig" || exit $?
        echo "Done!. $file.sig generated."
        
    }

    #################
    #  VERIFY SIGN  #
    #################

    #Verify the sign of a file with your public key
    verify_file() {
        local file=$1
        local sig=$file.sig

        [[  -e $file ]] || general_err "Couldn't find file: $file!"
        [[  -e $sig ]] || general_err "Couldn't find signature file: $sig!"

        if [[ ! -e $pkcs8_key ]]; then
            general_err "Couldn't find your public key: $pkcs8_key!. Try $0 -p $actual_profile -g to generate one"
        fi
        echo "Verifying $file with your public key $pkcs8_key"

        openssl dgst -$dgst_algo -verify $pkcs8_key -signature "$sig" "$file" || exit $?
    }
    

    ###############
    #  MAIN BODY  #
    ###############
    

    while getopts ":hedgp:s:v:" opt
    do
      case $opt in
        h|help      )  usage; exit 0   ;;
        e|encrypt   )  cmd=encrypt     ;;
        d|decrypt   )  cmd=decrypt     ;;
        g|generate  )  cmd=generate    ;;
        p|profile   )  set_keys_profile "$OPTARG"   ;;
        s|sign      )  sign_file "$OPTARG" ; exit 0 ;;
        v|verify    )  verify_file "$OPTARG" ; exit 0 ;;
        : )  echo -e "Option $OPTARG needs an argument.\nTry '$0 -h' for more information"; exit 1 ;; 
        * )  echo -e "Option does not exist : $OPTARG. \nTry '$0 -h' for more information"; exit 1 ;; 
      esac  
    done
    shift $(($OPTIND-1))

    if [[ $cmd == encrypt ]]; then
        #If passed a destination file/dir 
        if [[ -n $1 ]] ; then
            vault_file=$1
        else
            general_err "You must pass a file/dir to encrypt."
        fi
    elif [[ $cmd == decrypt ]]; then
        #If passed a tgz 
        [[ -n $1 ]] && tgz=$1
    fi

    #sane $vault_file (expect maximum one ending /)
    [[ ${vault_file: -1} == / ]] && vault_file=${vault_file:0:-1}

    #Execute the option
    $cmd 
}

do_vault "$@"



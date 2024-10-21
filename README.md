# do_vault

Generate secure open(ssl/ssh) keys 4096 and use them to encrypt/decrypt/sign/verify and to connect to other hosts.


#Install

```bash
git clone https://github.com/liloman/do_vault
cd do_vault/
./do_vault.sh 
Usage :  do_vault.sh [options] [--]

Options:
  -h|help            Display this message
  -e|encrypt  [ARG]  Encrypt ARG into vault.enc.tgz
  -d|decrypt  [ARG]  Decrypt ARG
  -g|generate [ARG]  Generate new keys for ARG
  -p|profile   ARG   Change profile
  -s|sign      ARG   Sign a file with your private key
  -v|verify    ARG   Verify a sign with your public key

Examples:
1.Generate your keys for the default profile:
  do_vault.sh -g
2.Generate your github's keys:
  do_vault.sh -p github -g
3.Encrypt 'my secret dir' with the default profile:
  do_vault.sh -e "my secret dir"
4.Decrypt vault.enc.tgz with backups@lenny's profile
  do_vault.sh -p backups@lenny -d
5.Decrypt private.tgz with the default profile:
  do_vault.sh -d private.tgz
6.Sign private.tgz with checksum's profile:
  do_vault.sh -p checksum -s private.tgz
7.Verify sign of private.tgz with checksum's profile:
  do_vault.sh -p checksum -v private.tgz
```

Requires:

```bash
dnf/apt/pacman/x install openssl
```

#Use

Generate a pair of rsa keys to github:

```bash
#do_vault.sh -p liloman@github.com -g 
1.Generating /home/liloman/.ssh/liloman@github.com.pem. Type a really strong passphrase!
....++
..........................................................................++
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
2.Generating /home/charly/.ssh/liloman@github.com.pub
Enter passphrase:
3.Generating /home/charly/.ssh/liloman@github.com.pub.pkcs8
Done. Keys for profile:"liloman@github.com" generated!
To login with ssh:
ssh-copy-id -f -i /home/charly/.ssh/liloman@github.com.pub remote-machine
#
```

You just generated a 4096 key with proper permissions on ~/.ssh for your profile: liloman@github.com.
Now you can use it to encrypt/decrypt with:

```bash
#do_vault.sh -p liloman@github.com -e firefox/
Encrypting firefox/ directory for profile: liloman@github.com
============================================================
1.Generating unique /dev/shm/secret_key of 500 bytes 
2.Generating /dev/shm/secret_key.enc with rsa 4096 bits
3.Generating metadata file /dev/shm/file.esp.enc with rsa 4096 bits
4.Generating files.enc with aes-256-cbc KDF SHA256 with /dev/shm/secret_key
5.Doing HMAC of files.enc with /dev/shm/secret_key
6.Packing /dev/shm/secret_key.enc, /dev/shm/file.esp.enc, files.enc and /dev/shm/files.hmac into firefox.enc.tgz
7.Cleanning up files
Done. File firefox.enc.tgz generated!
You can safely now delete firefox using shred -uzf or rm -rf if you wish
#
```

So it just takes the profile and -e to encrypt with the target dir and generate a encrypted tar.gz of that dir. You can move that dir to the cloud or wherever you want.


Later on you want to decrypt it so:

```bash
#do_vault.sh -p liloman@github.com -d firefox.enc.tgz
Decrypting firefox.enc.tgz for profile: liloman@github.com
============================================
Enter pass phrase for /home/charly/.ssh/liloman@github.com.pem:
1.Decrypting unique /dev/shm/secret_key.enc
2.Decrypting metadata file /dev/shm/file.esp.enc
3.Checking HMAC of files.enc with /dev/shm/secret_key
4.Decrypting files.enc with aes-256-cbc KDF SHA256 and salt=8420E15774C0F76D
firefox/
firefox/prefs.js
firefox/logins.json
firefox/places.sqlite-shm
firefox/HTTPSEverywhereUserRules/
...
5.Cleanning up files
Done. firefox.enc.tgz decrypted into firefox!
#
```

You have a server and want to connect to it:

```bash
#do_vault.sh -p user@my-server -g
1.Generating /home/charly/.ssh/user@my-server.pem. Type a really strong passphrase!
........................................++
..........................++
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
2.Generating /home/charly/.ssh/user@my-server.pub
Enter passphrase:
3.Generating /home/charly/.ssh/user@my-server.pub.pkcs8
Done. Keys for profile:"user@my-server" generated!
To login with ssh:
ssh-copy-id -f -i /home/charly/.ssh/user@my-server.pub remote-machine
# ssh-copy-id -f -i /home/charly/.ssh/user@my-server.pub my-server
...
```

Now add it to your ~/.ssh/config:

```bash
Host server2
    HostName my-server
    User user
    IdentityFile ~/.ssh/user@my-server.pem
```

And finally connect to it with:

```bash
#ssh server2
Enter PEM pass phrase:
my-server motd ....
user@my-server#
```


If you include a file called prepare_vault.sh in your dir it will be executed before encrypt the dir and after decrypting it. I use it for multiple purposes so that it is implemented, think about it as a secret auto installer/uninstaller. ;) 


#Spec

It generates a pair of 4096 rsa keys with a passphrase and use a random 500 bytes key to encrypt each dir with aes-256-cbc by default, so best of luck trying to decrypt it. :D

It generates a new 500 bytes random aes key everytime you encrypt something so you can safely use it and save it in the cloud the same dir.


#Why

Because openssl is good enough? :) 
You will always have to generate openssl/ssh for any work in Linux so you better have a standar way to manage your keys and not "trust" your default keys.

keybase or gpg will be something different, for now and my use case this is what I need.


#TODO

- [ ] Implement the [new PBKDF2](https://github.com/openssl/openssl/pull/2083) when done
- [ ] Command line options to change key lengths and algorithms ?


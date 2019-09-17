USA - 08/22/2008

ABOUT 

Rinecrypt--so called because the AES algorithm is called rijndael,
pronounced rinedall--is a file encryptor/decryptor, on a *NIX machine.
It is meant to decrypt only files encrypted with rinecrypt. This program
uses the AES algorithm made available by Brian Gladman, with a 256-bit
block size. It also uses OpenSSL's implementation of SHA-512. 
This version utilizes X86_64 assembly implementations of AES, and the
SHA-512 Block processing algorithms.

ARCHITECTURE 

This program has been successfully used on x86 32-bit little-endian 
architecture. It has not been tested on any others. 

COMPATIBILITY 

	This version of Rinecrypt is compatible with itself. This version
	(0.9.9.8) is not, however, compatible with previous versions of rinecrypt.
	This is due to the fact that I have simplified the methods of file
	authentication so that upon decryption the receiver knows that the
	encrypted file hasn't been forged or counterfeited by an attacker. This
	means that you MUST use the version you used to encrypt a file, to
	decrypt that file. However, if you have used a previous version of
	rinecrypt to encrypt your data, the odds of that data being unreadable
	except to the key-maker are still the same. The only difference would be
	that you can't know the authenticity of that encrypted file, the
	ciphertext would be apocryphal. This version of Rinecrypt has added
	AUTHENTICATION, specifically for data that has already been ENCRYPTED.
	Bottom line is your data are STILL SAFE.

SPEED
 On an 3200 Mhz Core2 Quad:
 encryption was 55.05 MB/sec
 decryption was 60.42 MB/sec

 This includes both encryption/decryption and hashing.

HOW IT WORKS

	ENCRYPTION

		  Rinecrypt encrypts a file using the AES algorithm and a 256-bit key.
		This key is derived from the user entered password and a 16 byte random
		salt, which are used to derive the AES key and the MAC key for
		authentication. To ensure maximum security I highly recommend using at
		least a 36 byte random string as the key ot be entered on the command
		line. On decryption, after rinecrypt has been properly activated using
		the correct options, it displays the ID of the ciphertext and then
		prompts the user to enter a password. When entering any data using
		rinecrypt the terminal (this is a CLI program) is blanked, so that no
		one can see what you type on the screen as you type it.
		  Rinecrypt has the ability to hold sensitive variables resident in RAM
		only, this option requires root privileges, however, since 'mlock' is
		setuid. That is to say that these variables aren't allowed to be written
		to disk. This feature has been borrowed from GnuPG 1.2.1.This means that
		you MUST have this privilege to use it. The root user has such
		privileges. If you can't use setuid programs, sensitive bytes are liable
		to be written to disk, even though these bytes are cleared by rinecrypt
		after their use, there is still a chance that they can be obtained by an
		attacker, especially if they have access to your system while rinecrypt
		is running. After the user has entered the password twice correctly,
		rinecrypt will use this password to derive the AES key.
		  After encryption is completed rinecrypt outputs three (3) very important
		strings to the terminal. These strings are: 1) the file ID, 2) the key
		derivation salt, and 3) the ciphertext MAC. The file ID is a random 16
		byte string that serves as the internal name of the ciphertext, as well
		as an identifier, so that the user knows which key + salt pair goes with
		which file ID, and using these can determine the file MAC, and thus
		verify the authenticity of the ciphertext. This is also done to make the
		task of identifying the ciphertext easier. Say you want to encrypt ten
		files, and transmit them in a certain order. Or you have many files and
		aren't sure which one is which, this makes that easier.
		  The salt is used for the key derivation method. The AES key, as well as
		the MAC key are derived from the password and this salt. The salt is to
		be kept secret by-the-way. The MAC is used to authenticate the
		ciphertext. If for a certain file ID, a key and salt pair used to
		generate the file MAC on encryption, does not give the same MAC on
		decryption, then the ciphertext was intercepted and adulterated by an
		attacker along the way.

		example of what the encryption output looks like:

		CT ID:                          AE5A 6682B2CBD4F4C0 906581 FBC50C Sat Aug 23 12:43:29 2008
		Salt:              74 00 18 D986 7B26 45CF84AD 0FB5 486729CC4802D567F858316DA455756D8BF1DA
		CT MAC:            B02B9CE4 CB7F7932 9ECB14F4 C38889FB 4DB4C9CF 9A46482D B77722C9 1D31AD44

		The spaces are only for formatting purposes and not necessary for decryption.

	DECRYPTION

		 Upon decryption, rinecrypt first outputs to the terminal, the file ID of
		the ciphertext. This ID should match the one obtained from encryption.
		Rinecrypt prompts the user to enter the password associated with that
		file ID. Then rinecrypt prompts the user to enter the salt associated
		with that file ID, this key + salt pair are then used to generate the
		AES key, as well as the MAC key. Then using this MAC key, rinecrypt
		calculates the MAC for the ciphertext, at which point rinecrypt prompts
		the user to enter the MAC received on encryption.

		--An aside. The implementation to prompt the user to enter the
		transmitted MAC is not strictly necessary, you may change it if you want
		to. The MAC generated on decryption from the key + salt pair associated
		with the file ID, can simply be printed on the screen and then the user
		can confirm that this matches the one he received. If they don't match,
		then either the file was not authenticated, or the user does not have
		the correct key+salt pair, in which case the decrypted file will be
		gibberish. I opted to make the user enter the MAC to cut dwn no tyipos,
		as well as to not decrypt if the MACs do not match, as this would be
		useless if the file were apocryphal.

		 This Mac is a truncated hash of an HMAC using SHA-512. Once the user has
		entered this MAC twice correctly, rinecrypt then goes on to verify this
		MAC, with the one generated from the ciphertext on encryption. If they
		match, then this means that the ciphertext has not been tampered with or
		forged.

	THE CIPHERTEXT HEADER

		The header created in the ciphertext upon encryption consists of 1) The
		rinecrypt file extension "RAES" (rincecrypt, aes-get it ;-). 2) two bytes
		which make up the ciphertext version (the version of rincerypt used to
		encrypt the ciphertext, cast from a 'short' two a 2 byte string) 3) the
		16 byte file ID, which includes a timestamp as well.

	METHODS OF AUTHENTICATION

		Rinecrypt uses a SHA-512 HMAC with a key derived from the password, and a
		random salt. This method is so much simpler than what I had done
		previously. In previous version of rinecrypt there were two, non-secret
		salts, located in the ciphertext header, which were used for password
		verifications as well as authentication. Now there is only one salt,
		which is secret, that used with a KDF (key-derivation function) in order
		to securely derive a key for encryption, and one for authentication,
		using only the user entered string and a random salt.

	SECRET DATA

		Obviously, the encryption password is secret, as well as the salt. The
		salt is secret because it is used in the KDF to derive the MAC key,
		which is used to authenticate the ciphertext, although you can't derive
		the MAC key with just the salt, but better to be safe than sorry.

	THE KDF

		I use Gladman's implementation of PBKDF2 using sha-512, 
		to derive the AES key from the user entered password and 
		the randomly gotten salt.

TRANSMISSION OF SECRET DATA 

	The best and most secure way to transmit the password, and the salt and
	MAC, is using a public key infrastructure. PGP or some such should work.
	I prefer GnuPG. 


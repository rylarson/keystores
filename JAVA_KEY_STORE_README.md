Java Key Store
==============

There are quite a few pieces that go into implementing a Java key store that we had to roll ourselves

## Encrypted private key info

[Keystores::Jks::EncryptedPrivateKeyInfo](lib/keystores/jks/encrypted_private_key_info.rb)

PKCS#8 defines the following syntax for an encrypted private key:

```
EncryptedPrivateKeyInfo ::=  SEQUENCE {
     encryptionAlgorithm   AlgorithmIdentifier,
     encryptedData   OCTET STRING }
```

Java's implementation actually encodes the following:

```
EncryptedPrivateKeyInfo ::=  SEQUENCE {
     SEQUENCE {
     null,
     encryptionAlgorithm   AlgorithmIdentifier},
     encryptedData   OCTET STRING }
```

For some reason, they wrap the PKCS8 sequence in another sequence, and throw a null in there for good measure.

## Key protector

[Keystores::Jks::KeyProtector](lib/keystores/jks/key_protector.rb)

This class is pretty much a direct port of `sun.security.provider.KeyProtector`.
It implements a proprietary PBE of sorts.

TODO, I would like to implement this as a proper `OpenSSL::Cipher` object.

## PKCS8 Key

This file cracks open the `OpenSSL::PKey` classes and enables them to both parse and encode keys
in PKCS#8 format. This is implemented for `EC`, `RSA`, and `DSA` keys.

### Parsing

Parsing is implemented as replacing the original `initialize` method with one that converts the DER
encoded key to PEM, and then calls the original `initialize` method. This is because for some reason,
the built in `OpenSSL::PKey` object constructors can parse a PEM encoded PKCS8 key just fine, but it
blows up on a DER encoded key.

This provides a method `OpenSSL::PKey.pkcs8_parse` that parses the ASN.1 encoded key structure, extracts
the key type, and returns the correct `OpenSSL::PKey` object.

### Encoding

This provides a method `OpenSSL::PKey::{RSA,DSA,EC}.to_pkcs8` that encodes each key type into its correct
PKCS#8 format. The Ruby OpenSSL wrapper doesn't give you access to PKCS8 capabilities in OpenSSL, and even if
it did, not all versions of openssl that are packaged with ruby implement PKCS8 encoding.

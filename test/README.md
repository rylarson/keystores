### Testing Keystores

#### clientkeystore.jks

Created using:

```
keytool -keystore test.jks -genkey -alias test_private_key_entry
keytool -export -alias test_private_key_entry -file certificate.crt -keystore test.jks
keytool -import -alias test_trusted_certificate_entry -file certificate.crt -keystore test.jks
keytool -genkey -keyalg RSA -alias test_rsa_private_key_entry -keystore test.jks -storepass keystores -validity 3600 -keysize 2048
```

Password: keystores

This is a Java Key Store with a DSA PrivateKeyEntry, DSA TrustedCertificateEntry, and an RSA PrivateKeyEntry
that is used for testing the `Keystores::JavaKeystore` class.

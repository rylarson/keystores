### Testing Keystores

#### clientkeystore.jks

Created using:

```
keytool -keystore test.jks -genkey -alias test_private_key_entry
keytool -export -alias test_private_key_entry -file certificate.crt -keystore test.jks
keytool -import -alias test_trusted_certificate_entry -file certificate.crt -keystore test.jks
```

Password: keystores

This is a Java Key Store with a single PrivateKeyEntry and a single TrustedCertificateEntry that is used for testing
the `Keystores::JavaKeystore` class.

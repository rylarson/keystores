require 'spec_helper'
require 'keystores'
require 'openssl'
require 'stringio'

describe OpenSSL::JKS do
  it 'can load a keystore containing a PrivateKeyEntry and a TrustedCertificateEntry' do
    keystore = OpenSSL::JKS.new
    keystore.load('test/test.jks', 'keystores')

    expect(keystore.get_type).to eq(OpenSSL::JKS::TYPE)
    expect(keystore.size).to eq(4)
    expected_aliases = ['test_private_key_entry',
                        'test_trusted_certificate_entry',
                        'test_rsa_private_key_entry',
                        'test_ec_private_key_entry']
    expect(keystore.aliases).to contain_exactly(*expected_aliases)

    expected_aliases.each do |expected_alias|
      expect(keystore.contains_alias(expected_alias)).to be_truthy
      expect(keystore.contains_alias(expected_alias.reverse)).to be_falsey
    end

    expect(keystore.is_certificate_entry('test_private_key_entry')).to be_falsey
    expect(keystore.is_key_entry('test_private_key_entry')).to be_truthy

    expect(keystore.is_certificate_entry('test_trusted_certificate_entry')).to be_truthy
    expect(keystore.is_key_entry('test_trusted_certificate_entry')).to be_falsey

    expected_certificate = OpenSSL::X509::Certificate.new(IO.binread('test/trusted_certificate_jks.crt'))
    actual_certificate = keystore.get_certificate('test_trusted_certificate_entry')

    # We have to DER encode both of the certificates because OpenSSL::X509::Certificate doesn't implement equal?
    expect(actual_certificate.to_der).to eq(expected_certificate.to_der)

    actual_certificate = keystore.get_certificate('test_private_key_entry')

    # We have to DER encode both of the certificates because OpenSSL::X509::Certificate doesn't implement equal?
    expect(actual_certificate.to_der).to eq(expected_certificate.to_der)

    # It just so happens that the trusted cert entry is first in our test key store.
    expect(keystore.get_certificate_alias(expected_certificate)).to eq('test_trusted_certificate_entry')

    expect(keystore.get_certificate_chain('test_trusted_certificate_entry')).to be_nil
    expect(keystore.get_certificate_chain('test_private_key_entry').size).to eq(1)
    expect(keystore.get_certificate_chain('test_private_key_entry')[0].to_der).to eq(expected_certificate.to_der)

    expect(keystore.get_key('test_trusted_certificate_entry', 'keystores')).to be_nil
    expect(keystore.get_key('doesnt_exist', 'keystores')).to be_nil

    expect { keystore.get_key('test_private_key_entry', nil) }.to raise_error(IOError)
    expect(keystore.get_key('test_private_key_entry', 'keystores')).to be_a(OpenSSL::PKey::DSA)

    expect { keystore.get_key('test_rsa_private_key_entry', nil) }.to raise_error(IOError)
    expect(keystore.get_key('test_rsa_private_key_entry', 'keystores')).to be_a(OpenSSL::PKey::RSA)

    expect { keystore.get_key('test_ec_private_key_entry', nil) }.to raise_error(IOError)
    expect(keystore.get_key('test_ec_private_key_entry', 'keystores')).to be_a(OpenSSL::PKey::EC)

    keystore.delete_entry('test_trusted_certificate_entry')
    expect(keystore.size).to eq(3)
    expect(keystore.contains_alias('test_trusted_certificate_entry')).to be_falsey
    expect(keystore.contains_alias('test_private_key_entry')).to be_truthy
    expect(keystore.aliases).to contain_exactly('test_private_key_entry', 'test_rsa_private_key_entry', 'test_ec_private_key_entry')

    # Now when we ask for the alias given the certificate, we get the one back from private key entry
    expect(keystore.get_certificate_alias(expected_certificate)).to eq('test_private_key_entry')
  end

  context 'writing a keystore' do
    # TODO add integration tests to make sure that Java can actually read this
    it 'correctly writes a keystore that it read' do
      keystore = OpenSSL::JKS.new
      keystore.load('test/test.jks', 'keystores')

      java_generated_key = keystore.get_key('test_private_key_entry', 'keystores')
      java_generated_certificate = keystore.get_certificate('test_trusted_certificate_entry')

      stored = StringIO.new
      stored.set_encoding('BINARY', 'BINARY')
      keystore.store(stored, 'keystores')
      stored.rewind

      keystore = OpenSSL::JKS.new
      keystore.load(stored, 'keystores')

      ruby_generated_certificate = keystore.get_certificate('test_trusted_certificate_entry')
      expect(ruby_generated_certificate.to_der).to (eq(java_generated_certificate.to_der))

      ruby_generated_key = keystore.get_key('test_private_key_entry', 'keystores')
      expect(ruby_generated_key.to_der).to (eq(java_generated_key.to_der))
    end
  end

  context 'with an invalid file format' do
    it 'raises an error if the password is incorrect' do
      keystore = OpenSSL::JKS.new
      expect {
        keystore.load('test/test.jks', 'keystores'.reverse)
      }.to raise_error(IOError, 'Keystore was tampered with, or password was incorrect')
    end

    it 'raises an error if the magic is incorrect' do
      keystore = OpenSSL::JKS.new
      expect {
        keystore.load(StringIO.new([0xdeefdeef].pack('N')), 'keystores')
      }.to raise_error(IOError, 'Invalid keystore format')
    end

    it 'raises an error if the magic is correct but the version is not' do
      keystore = OpenSSL::JKS.new
      expect {
        keystore.load(StringIO.new([OpenSSL::JKS::MAGIC, 0x03].pack('N*')), 'keystores')
      }.to raise_error(IOError, 'Invalid keystore format')
    end
  end
end

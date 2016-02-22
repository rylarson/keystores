require 'keystores/keystore'
require 'keystores/jks/key_protector'
require 'keystores/jks/encrypted_private_key_info'
require 'thread'
require 'openssl'

module Keystores
  # An implementation of a Java Key Store (JKS) Format
  class JavaKeystore < Keystore

    TYPE = 'JKS'

    # Defined by JavaKeyStore.java
    MAGIC = 0xfeedfeed
    VERSION_1 = 0x01
    VERSION_2 = 0x02

    def initialize
      @entries = {}
      @entries_mutex = Mutex.new
    end

    def aliases
      @entries.keys
    end

    def contains_alias(aliaz)
      @entries.has_key?(aliaz)
    end

    def delete_entry(aliaz)
      @entries_mutex.synchronize { @entries.delete(aliaz) }
    end

    def get_certificate(aliaz)
      entry = @entries[aliaz]
      unless entry.nil?
        if entry.is_a? TrustedCertificateEntry
          entry.certificate
        elsif entry.is_a? KeyEntry
          entry.certificate_chain[0]
        else
          nil
        end
      end
    end

    def get_certificate_alias(certificate)
      @entries.each do |aliaz, entry|
        if entry.is_a? TrustedCertificateEntry
          # We have to DER encode both of the certificates because OpenSSL::X509::Certificate doesn't implement equal?
          return aliaz if certificate.to_der == entry.certificate.to_der
        elsif entry.is_a? KeyEntry
          # We have to DER encode both of the certificates because OpenSSL::X509::Certificate doesn't implement equal?
          return aliaz if certificate.to_der == entry.certificate_chain[0].to_der
        end
      end
      nil
    end

    def get_certificate_chain(aliaz)
      entry = @entries[aliaz]
      if !entry.nil? && entry.is_a?(KeyEntry)
        entry.certificate_chain
      else
        nil
      end
    end

    def get_key(aliaz, password)
      entry = @entries[aliaz]

      # This somewhat odd control flow mirrors the Java code for ease of porting
      # TODO clean this up
      if entry.nil? || !entry.is_a?(KeyEntry)
        return nil
      end

      if password.nil?
        raise IOError.new('Password must not be nil')
      end

      encrypted_private_key = entry.encrypted_private_key
      encrypted_private_key_info = Keystores::Jks::EncryptedPrivateKeyInfo.new(encrypted_private_key)
      Keystores::Jks::KeyProtector.new(password).recover(encrypted_private_key_info)
    end

    def get_type
      TYPE
    end

    def is_certificate_entry(aliaz)
      !@entries[aliaz].nil? && @entries[aliaz].is_a?(TrustedCertificateEntry)
    end

    def is_key_entry(aliaz)
      !@entries[aliaz].nil? && @entries[aliaz].is_a?(KeyEntry)
    end

    def load(key_store_file, password)
      @entries_mutex.synchronize do
        key_store_bytes = IO.binread(key_store_file)
        # We pass this Message Digest around and add all of the bytes we read to it so we can verify integrity
        md = get_pre_keyed_hash(password)

        magic = read_int!(key_store_bytes, md)
        version = read_int!(key_store_bytes, md)

        if magic != MAGIC || (version != VERSION_1 && version != VERSION_2)
          raise IOError.new('Invalid keystore format')
        end

        count = read_int!(key_store_bytes, md)

        count.times do
          tag = read_int!(key_store_bytes, md)

          if tag == 1 # Private Key entry
            key_entry = KeyEntry.new
            aliaz = read_utf!(key_store_bytes, md)
            time = Time.at(read_long!(key_store_bytes, md))

            key_entry.creation_date = time

            private_key_length = read_int!(key_store_bytes, md)
            encrypted_private_key = key_store_bytes.slice!(0..(private_key_length - 1))
            md << encrypted_private_key

            key_entry.encrypted_private_key = encrypted_private_key

            number_of_certs = read_int!(key_store_bytes, md)

            certificate_chain = []

            number_of_certs.times do
              certificate_chain << read_certificate(key_store_bytes, version, md)
            end

            key_entry.certificate_chain = certificate_chain
            @entries[aliaz] = key_entry
          elsif tag == 2 # Trusted Certificate entry
            trusted_cert_entry = TrustedCertificateEntry.new
            aliaz = read_utf!(key_store_bytes, md)
            time = Time.at(read_long!(key_store_bytes, md))

            trusted_cert_entry.creation_date = time
            certificate = read_certificate(key_store_bytes, version, md)
            trusted_cert_entry.certificate = certificate
            @entries[aliaz] = trusted_cert_entry
          else
            raise IOError.new('Unrecognized keystore entry')
          end
        end

        unless password.nil?
          verify_key_store_integrity(key_store_bytes, md)
        end
      end
    end

    def set_certificate_entry(aliaz, certificate)
      super
    end

    def set_key_entry(aliaz, key, certificate_chain, password=nil)
      super
    end

    def size
      @entries.size
    end

    def store(key_store_file, password)
      super
    end

    private

    def read_certificate(key_store_bytes, version, md)
      # If we are a version 2 JKS, we check to see if we have the right certificate type
      # Version 1 JKS format unconditionally assumed X509
      if version == 2
        cert_type = read_utf!(key_store_bytes, md)
        if cert_type != 'X.509' && cert_type != 'X509'
          raise IOError.new("Unrecognized certificate type: #{cert_type}")
        end
      end
      certificate_length = read_int!(key_store_bytes, md)
      certificate = key_store_bytes.slice!(0..(certificate_length - 1))
      md << certificate
      OpenSSL::X509::Certificate.new(certificate)
    end

    # Derive a key in the same goofy way that Java does
    def get_pre_keyed_hash(password)
      md = OpenSSL::Digest::SHA1.new
      passwd_bytes = []
      password.unpack('c*').each do |byte|
        passwd_bytes << (byte >> 8)
        passwd_bytes << byte
      end
      md << passwd_bytes.pack('c*')
      md << 'Mighty Aphrodite'.force_encoding('UTF-8')
      md
    end

    def verify_key_store_integrity(key_store_bytes, md)
      # The remaining key store bytes are the password based hash
      actual_hash = key_store_bytes
      computed_hash = md.digest

      # TODO, change how we compare these to defend against timing attacks even though JAVA doesn't
      if actual_hash != computed_hash
        raise IOError.new('Keystore was tampered with, or password was incorrect')
      end
    end

    # Java uses DataInputStream#readInt() which is defined as reading 4 bytes and interpreting it as an int
    def read_int!(bytes, md)
      bytes = bytes.slice!(0..3)
      md << bytes
      bytes.unpack('N')[0]
    end

    # Java uses DataInputStream#readUnsignedShort() which is defined as reading 2 bytes and interpreting it as an int
    def read_unsigned_short!(bytes, md)
      bytes = bytes.slice!(0..1)
      md << bytes
      bytes.unpack('n')[0]
    end

    # Java uses DataInputStream#readUTF which does a bunch of crap to read a modified UTF-8 format
    # TODO, this is a bit of a hack, but seems to work fine. We just assume we get a string out of the array
    def read_utf!(bytes, md)
      utf_length = read_unsigned_short!(bytes, md)
      bytes = bytes.slice!(0..(utf_length - 1))
      md << bytes
      bytes
    end

    # Java uses DataInputStream#readLong which is defined as reading 8 bytes and interpreting it as a signed long
    def read_long!(bytes, md = nil)
      bytes = bytes.slice!(0..7)
      md << bytes
      bytes.unpack('q')[0]
    end

    class KeyEntry
      attr_accessor :creation_date, :encrypted_private_key, :certificate_chain
    end

    class TrustedCertificateEntry
      attr_accessor :creation_date, :certificate
    end
  end
end

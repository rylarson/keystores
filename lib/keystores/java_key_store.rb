require 'keystores/keystore'
require 'keystores/jks/key_protector'
require 'keystores/jks/encrypted_private_key_info'
require 'thread'
require 'openssl'
require 'date'

module Keystores
  # An implementation of a Java Key Store (JKS) Format
  class JavaKeystore < Keystore

    TYPE = 'JKS'

    # Defined by JavaKeyStore.java
    MAGIC = 0xfeedfeed
    VERSION_1 = 0x01
    VERSION_2 = 0x02
    KEY_ENTRY_TAG = 1
    TRUSTED_CERTIFICATE_ENTRY_TAG = 2

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
      encrypted_private_key_info = Keystores::Jks::EncryptedPrivateKeyInfo.new(:encoded => encrypted_private_key)
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
        key_store_bytes = key_store_file.respond_to?(:read) ? key_store_file.read : IO.binread(key_store_file)
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

          if tag == KEY_ENTRY_TAG
            key_entry = KeyEntry.new
            aliaz = read_utf!(key_store_bytes, md)
            time = read_long!(key_store_bytes, md)

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
          elsif tag == TRUSTED_CERTIFICATE_ENTRY_TAG
            trusted_cert_entry = TrustedCertificateEntry.new
            aliaz = read_utf!(key_store_bytes, md)
            time = read_long!(key_store_bytes, md)

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
      @entries_mutex.synchronize do
        entry = @entries[aliaz]
        if !entry.nil? && entry.is_a?(KeyEntry)
          raise ArgumentError.new('Cannot overwrite own certificate')
        end

        entry = TrustedCertificateEntry.new
        entry.certificate = certificate
        # Java uses new Date().getTime() which returns milliseconds since epoch, so we do the same here with %Q
        entry.creation_date = DateTime.now.strftime('%Q').to_i

        @entries[aliaz] = entry
      end
    end

    def set_key_entry(aliaz, key, certificate_chain, password)
      @entries_mutex.synchronize do
        entry = @entries[aliaz]
        if !entry.nil? && entry.is_a?(TrustedCertificateEntry)
          raise ArgumentError.new('Cannot overwrite own key')
        end

        entry = KeyEntry.new
        # Java uses new Date().getTime() which returns milliseconds since epoch, so we do the same here with %Q
        entry.creation_date = DateTime.now.strftime('%Q').to_i
        entry.encrypted_private_key = Keystores::Jks::KeyProtector.new(password).protect(key)
        entry.certificate_chain = [certificate_chain].flatten

        @entries[aliaz] = entry
      end
    end

    def size
      @entries.size
    end

    def store(key_store_file, password)
      @entries_mutex.synchronize do
        # password is mandatory when storing
        if password.nil?
          raise ArgumentError.new("password can't be null")
        end

        md = get_pre_keyed_hash(password)

        io = key_store_file.respond_to?(:write) ? key_store_file : File.open(key_store_file, 'wb')

        write_int(io, MAGIC, md)
        # Always write the latest version
        write_int(io, VERSION_2, md)
        write_int(io, @entries.size, md)

        @entries.each do |aliaz, entry|
          if entry.is_a? KeyEntry
            write_int(io, KEY_ENTRY_TAG, md)
            write_utf(io, aliaz, md)
            write_long(io, entry.creation_date, md)
            write_int(io, entry.encrypted_private_key.length, md)
            write(io, entry.encrypted_private_key, md)

            certificate_chain = entry.certificate_chain
            chain_length = certificate_chain.nil? ? 0 : certificate_chain.length

            write_int(io, chain_length, md)

            unless certificate_chain.nil?
              certificate_chain.each { |certificate| write_certificate(io, certificate, md) }
            end
          elsif entry.is_a? TrustedCertificateEntry
            write_int(io, TRUSTED_CERTIFICATE_ENTRY_TAG, md)
            write_utf(io, aliaz, md)
            write_long(io, entry.creation_date, md)
            write_certificate(io, entry.certificate, md)
          else
            raise IOError.new('Unrecognized keystore entry')
          end
        end
        # Write the keyed hash which is used to detect tampering with
        # the keystore (such as deleting or modifying key or
        # certificate entries).
        io.write(md.digest)
        io.flush
      end
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

    def write_certificate(file, certificate, md)
      encoded = certificate.to_der
      write_utf(file, 'X.509', md)
      write_int(file, encoded.length, md)
      write(file, encoded, md)
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
    def read_long!(bytes, md)
      bytes = bytes.slice!(0..7)
      md << bytes
      bytes.unpack('q>')[0]
    end

    # Java uses DataOutputStream#writeUTF to write the length + string
    def write_utf(file, string, md)
      write_short(file, string.length, md)
      write(file, string, md)
    end

    # Java uses DataInputStream#writeInt() which writes a 32 bit integer
    def write_int(file, int, md)
      int = [int].pack('N')
      md << int
      file.write(int)
    end

    # Java uses DataInputStream#writeShort() which writes a 16 bit integer
    def write_short(file, short, md)
      short = [short].pack('n')
      md << short
      file.write(short)
    end

    # Java uses DataInputStream#writeLong which writes a 64 bit integer
    def write_long(file, long, md)
      long = [long].pack('q>')
      md << long
      file.write(long)
    end

    def write(file, bytes, md)
      md << bytes
      file.write(bytes)
    end

    class KeyEntry
      attr_accessor :creation_date, :encrypted_private_key, :certificate_chain
    end

    class TrustedCertificateEntry
      attr_accessor :creation_date, :certificate
    end
  end
end

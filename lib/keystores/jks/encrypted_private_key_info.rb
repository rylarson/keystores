# This class implements the EncryptedPrivateKeyInfo type,
# which is defined in PKCS #8 as follows:
#
#   EncryptedPrivateKeyInfo ::=  SEQUENCE {
#      encryptionAlgorithm   AlgorithmIdentifier,
#      encryptedData   OCTET STRING }
#

require 'openssl'

module Keystores
  module Jks
    class EncryptedPrivateKeyInfo
      attr_accessor :encrypted_data, :algorithm, :encoded

      # You can pass either an ASN.1 encryptedPrivateKeyInfo object
      # or the encrypted bytes and the encryption algorithm.
      #
      # @param [Hash] opts
      # @option opts [String] :encoded The ASN.1 encoded encrypted private key info
      # @option opts [String] :algorithm The encryption algorithm
      # @option opts [String] :encrypted_data The encrypted key bytes
      def initialize(opts = {})
        # Parses from encoded private key
        if opts.has_key?(:encoded)
          encoded = opts[:encoded]
          @asn1 = OpenSSL::ASN1.decode(encoded)
          @encrypted_data = @asn1.value[1].value
          @algorithm = @asn1.value[0].value[0].value
          @encoded = encoded
        else
          @algorithm = opts[:algorithm]
          @encrypted_data = opts[:encrypted_data]
          @encoded = encode(@algorithm, @encrypted_data)
        end
      end

      private

      # Java actually encodes:
      #
      #   EncryptedPrivateKeyInfo ::=  SEQUENCE {
      #      SEQUENCE {
      #      null,
      #      encryptionAlgorithm   AlgorithmIdentifier},
      #      encryptedData   OCTET STRING }
      def encode(algorithm, encrypted_data)
        a = OpenSSL::ASN1::ObjectId.new(algorithm)
        null = OpenSSL::ASN1::Null.new(nil)
        oid_sequence = OpenSSL::ASN1::Sequence.new([a, null])
        d = OpenSSL::ASN1::OctetString.new(encrypted_data)
        OpenSSL::ASN1::Sequence.new([oid_sequence, d]).to_der
      end
    end
  end
end

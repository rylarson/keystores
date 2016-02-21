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

      # Parses from encoded private key
      def initialize(encoded)
        @asn1 = OpenSSL::ASN1.decode(encoded)
        @encrypted_data = @asn1.value[1].value
        @algorithm = @asn1.value[0].value[0].value
        @encoded = encoded
      end
    end
  end
end

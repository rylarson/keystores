require 'base64'
require 'openssl'

module Keystores
  module Jks
    class PKCS8Key

      class << self
        # Parse the correct type of OpenSSL::PKey from a der encoded PKCS8 private key
        def parse(der_bytes)
          to_open_ssl_p_key der_bytes
        end

        def encode(key)
          if key.is_a?(OpenSSL::PKey::DSA)
            encode_dsa_key(key)
          end
        end

        private

        def to_open_ssl_p_key(der_bytes)
          key_type = extract_key_type(der_bytes)
          pem = der_to_pem('PRIVATE KEY', der_bytes)
          OpenSSL::PKey.const_get(key_type).new(pem)
        end

        # The OpenSSL that is bundled with ruby (2.0 and 2.2.1) cannot handle a PKCS8 DER encoded private key
        # It can handle a PEM encoded PKCS8 key just fine though.
        #
        # TODO, this is a bit of a hack, I don't know how else we would do it though
        def box(tag, lines)
          lines.unshift "-----BEGIN #{tag}-----"
          lines.push "-----END #{tag}-----"
          lines.join("\n")
        end

        def der_to_pem(tag, der)
          box tag, Base64.strict_encode64(der).scan(/.{1,64}/)
        end

        def extract_key_type(der_bytes)
          asn1 = OpenSSL::ASN1.decode(der_bytes)
          asn1.value[1].value[0].value
        end

        def encode_dsa_key(dsa_key)
          params = dsa_key.params
          integer = OpenSSL::ASN1::Integer.new(OpenSSL::BN.new('0'))
          oid = OpenSSL::ASN1::ObjectId.new('DSA')
          p = OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(params['p']))
          q = OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(params['q']))
          g = OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(params['g']))
          param_sequence = OpenSSL::ASN1::Sequence.new([p, q, g])
          sequence = OpenSSL::ASN1::Sequence.new([oid, param_sequence])
          octet_string = OpenSSL::ASN1::OctetString.new(OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(params['priv_key'])).to_der)
          OpenSSL::ASN1::Sequence.new([integer, sequence, octet_string])
        end
      end
    end
  end
end

require 'base64'
require 'openssl'

module OpenSSL
  module PKey
    class EC
      original_initialize = instance_method(:initialize)

      define_method(:initialize) do |der_or_pem|
        init = original_initialize.bind(self)
        begin
          init.(der_or_pem)
        rescue Exception
          # If we blow up trying to parse the key, we might be der encoded PKCS8, and if we are, convert ourselves
          # to PEM and try again.
          init.(OpenSSL::PKey.der_to_pem(der_or_pem))
        end
      end

      def to_pkcs8
        integer = OpenSSL::ASN1::Integer.new(OpenSSL::BN.new('0'))
        oid = OpenSSL::ASN1::ObjectId.new('id-ecPublicKey')
        curve_name = OpenSSL::ASN1::ObjectId.new(self.group.curve_name)
        sequence = OpenSSL::ASN1::Sequence.new([oid, curve_name])
        octet_string = OpenSSL::ASN1::OctetString.new(encode_private_key.to_der)
        OpenSSL::ASN1::Sequence.new([integer, sequence, octet_string])
      end

      def to_pkcs8_der
        to_pkcs8.to_der
      end

      def to_pkcs8_pem
        to_pkcs8.to_pem
      end

      private

      # ASN.1 syntax for EC private keys from SEC 1 v1.5 (draft):
      #
      # ECPrivateKey ::= SEQUENCE {
      #   version INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
      #   privateKey OCTET STRING,
      #   parameters [0] ECDomainParameters {{ SECGCurveNames }} OPTIONAL,
      #   publicKey [1] BIT STRING OPTIONAL
      # }
      #
      # We currently ignore the optional parameters and publicKey fields.
      # We encode the parameters are as part of the curve name,
      # not in the private key structure. We do this because Java expects things
      # to be encoded this way
      def encode_private_key
        version = OpenSSL::ASN1::Integer.new(OpenSSL::BN.new('1'))
        # The private key is stored as the twos complement binary representation
        priv_key = OpenSSL::ASN1::OctetString(private_key.to_s(2))
        OpenSSL::ASN1::Sequence.new([version, priv_key])
      end
    end

    class RSA
      original_initialize = instance_method(:initialize)

      define_method(:initialize) do |der_or_pem|
        init = original_initialize.bind(self)
        begin
          init.(der_or_pem)
        rescue Exception
          # If we blow up trying to parse the key, we might be der encoded PKCS8, and if we are, convert ourselves
          # to PEM and try again.
          init.(OpenSSL::PKey.der_to_pem(der_or_pem))
        end
      end

      def to_pkcs8
        integer = OpenSSL::ASN1::Integer.new(OpenSSL::BN.new('0'))
        oid = OpenSSL::ASN1::ObjectId.new('rsaEncryption')
        sequence = OpenSSL::ASN1::Sequence.new([oid, OpenSSL::ASN1::Null.new(nil)])

        params = self.params
        version = OpenSSL::ASN1::Integer.new(OpenSSL::BN.new('0'))
        n = OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(params['n']))
        e = OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(params['e']))
        d = OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(params['d']))
        p = OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(params['p']))
        q = OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(params['q']))
        dmp1 = OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(params['dmp1']))
        dmq1 = OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(params['dmq1']))
        iqmp = OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(params['iqmp']))

        params_sequence = OpenSSL::ASN1::Sequence.new([version, n, e, d, p, q, dmp1, dmq1, iqmp])

        octet_string = OpenSSL::ASN1::OctetString.new(params_sequence.to_der)
        OpenSSL::ASN1::Sequence.new([integer, sequence, octet_string])
      end

      def to_pkcs8_der
        to_pkcs8.to_der
      end

      def to_pkcs8_pem
        to_pkcs8.to_pem
      end
    end

    class DSA
      original_initialize = instance_method(:initialize)

      define_method(:initialize) do |der_or_pem|
        init = original_initialize.bind(self)
        begin
          init.(der_or_pem)
        rescue Exception
          # If we blow up trying to parse the key, we might be der encoded PKCS8, and if we are, convert ourselves
          # to PEM and try again.
          init.(OpenSSL::PKey.der_to_pem(der_or_pem))
        end
      end

      def to_pkcs8
        params = self.params
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

      def to_pkcs8_der
        to_pkcs8.to_der
      end

      def to_pkcs8_pem
        to_pkcs8.to_pem
      end
    end

    # Parse the correct type of OpenSSL::PKey from a der encoded PKCS8 private key
    def self.pkcs8_parse(der_bytes)
      key_type = extract_key_type(der_bytes)
      OpenSSL::PKey.const_get(key_type).new(der_bytes)
    end

    private

    def self.extract_key_type(der_bytes)
      asn1 = OpenSSL::ASN1.decode(der_bytes)
      algorithm = asn1.value[1].value[0].value.downcase
      if algorithm.include? 'rsa'
        'RSA'
      elsif algorithm.include? 'ec'
        'EC'
      elsif algorithm.include? 'dsa'
        'DSA'
      end
    end

    def self.der_to_pem(der)
      box(Base64.strict_encode64(der).scan(/.{1,64}/))
    end

    def self.box(lines)
      lines.unshift '-----BEGIN PRIVATE KEY-----'
      lines.push '-----END PRIVATE KEY-----'
      lines.join("\n")
    end
  end
end

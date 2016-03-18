require 'base64'
require 'openssl'
require 'keystores/jks/pkcs8_key'

describe 'openssl PKCS#8 key' do
  context 'KAT' do
    context 'DSA' do

      # Encoded (plain text) DSA key obtained via debugger after decrypting from Java Key Store loaded in JVM
      PLAIN_KEY_PKCS8_DER = Base64.decode64('MIIBSwIBADCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2
USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4
O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmC
ouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCB
gLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhR
kImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoEFgIUb2aSH/GLWWT2EETZzPzImfyQsEo=')

      it 'encode and decode' do
        dsa_key = OpenSSL::PKey::DSA.new(PLAIN_KEY_PKCS8_DER)
        pkcs8_encoded_dsa_key = dsa_key.to_pkcs8
        expect(pkcs8_encoded_dsa_key.to_der).to eq(PLAIN_KEY_PKCS8_DER)
      end
    end
  end
end

require 'keystores/jks/key_protector'
require 'keystores/jks/encrypted_private_key_info'
require 'base64'
require 'openssl'
require 'keystores/jks/pkcs8_key'

describe Keystores::Jks::KeyProtector do
  context 'KAT' do
    context 'DSA' do
      DSA_PRIVATE_KEY_X = '635985380835263211676343411356410826303619510346'
      DSA_PRIVATE_KEY_P = '178011905478542266528237562450159990145232156369120674273274450314442865788737020770612695252123463079567156784778466449970650770920727857050009668388144034129745221171818506047231150039301079959358067395348717066319802262019714966524135060945913707594956514672855690606794135837542707371727429551343320695239'
      DSA_PRIVATE_KEY_Q = '864205495604807476120572616017955259175325408501'
      DSA_PRIVATE_KEY_G = '174068207532402095185811980123523436538604490794561350978495831040599953488455823147851597408940950725307797094915759492368300574252438761037084473467180148876118103083043754985190983472601550494691329488083395492313850000361646482644608492304078721818959999056496097769368017749273708962006689187956744210730'

      # Encoded (encrypted) DSA key obtained via debugger from Java Key Store loaded in JVM
      ENCODED_DATA_BASE_64 = 'MIIBizAOBgorBgEEASoCEQEBBQAEggF3pAu6N6wKaUj3pJA5LAGKH6RlYfFskU8zpLMb1nCftWZ/
OEvEBR4BLWZwFEaZmSdQnPYKVMNIvyxPD1BJ+tp/5UexxTsmC2uxHm+MOvfn6wAVrst7GAQcehoC
wQIG22cykp0HnKzMbXSyuMhLbTZj1mEb9zm99TyqkwUgr9VzKtaMAKDR/UQXJyzKcpugwpKQAwaq
22hEX8UKwlgXvasmPFbYkReKs9H54fPzlZH3x7GC3gsCuu15dAW6xzfTwGk2YgqrN9M+7sKy0gRX
Ev1PMNyBg9bDkSM3jHIL5v9Cy9aSPkZJFiTWs+eW+WxFrEygiBVT4/Of/haK12/6TCeFPUxYx3KS
AN//voZt8c441Y8K6COlw3nYC0ojF280E6fnObK6bZTQ695MAficLX+wQE5WVQg9WrUmEFMIdz8N
QIDUcQyBcVH38ZTiPgEcrOvnzG7T2XKCUHDVkVopkwdKm+dr8C3bzMJYSnQRPPMUtsn6JFyHnsUk'

      # Encoded (plain text) DSA key obtained via debugger after decrypting from Java Key Store loaded in JVM
      PLAIN_KEY_BASE_64 = 'MIIBSwIBADCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2
USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4
O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmC
ouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCB
gLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhR
kImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoEFgIUb2aSH/GLWWT2EETZzPzImfyQsEo='

      # DSA key returned from KeyProtector#protect(key) from Java
      ENCRYPTED_KEY_BASE_64 = 'MIIBizAOBgorBgEEASoCEQEBBQAEggF3YZoLSUkmGlvKgLjxqVVUtG8MwEjYmx1TrgZO19wXKGMZ
5ovhEo0NjsXgVuFwSIyfrq7zsBnfmzjQT5ia0NrRLnz3wuokrwbsx0+iSwFLFCSYiKWfQOlOPVL7
CXYM2lQxd7fAOKJfm/26rzFfdKhRUM7RuVimxEcju4Fn1c0MRPPuCgy7u6u+79nyp1moUhTdRHYv
TAnDf+08kwK43CP2Lgf5k2KfsZ24DUCtxDZZ1D0ZQ0eBMNvZow4Kn8QYtyy4NWfZDTONfjBmPQ0C
g0BJ8PCPkv/xbRajLVtp4ykQjQvN7Kld/oSo+TeXdOryklu072XVku5XnAopkk6Hy2672GdBXITd
Uk6Gk5/qNLDGk0Dwr6V6CesgQPDTT4/ITEV4rttXshI5mBOwFSqlU6HIftElCZVMx/euWLutmQLy
DlYHS27dgut//JYucECPg7V7zz/oDtaD5TBmUnS+zofogLp4Xy3bzMJYSnQRPPMUtsn6JFyHnsUk'

      ENCRYPTED_UNENCODED_KEY_BASE_64 = 'UM2oy9+ccSoT3YprrWqlJphYEZPXBze2NeiFWnHi9k+RfQU0l4CJBc42XtvpbFHFzA3ygkW6vOGj
QQpwwd+LUMgsXrk5ffpfcrrbS20QApA7KwdbM1cthmOws0mf2o/cGPPcm6IhYhNID7k53vYWr0lj
QmEvz4lI0QlCBubMtUlsja02qC2raHwvOcA8gqV1gByzNxQVy7cqg14JQ0w8G0yBT4AYYnxxoa/E
HAvQp0MywETmJNoFtP+/foW/2PzjD0qAOyaZVBwrCUwGSf6rep83rpJ56yBs11Q/ULPlSK++UvlA
+8q/uDdqIBNPufwfdi99Zrs9L5qgG2UE8xxEGqdG9yO/i1qlY6iUGN/Lyqcg3f0Lv9ofSD4zYLO0
BgK9MsmtqQ5b4aWsM6anoj41S8U/f/qg5AkJB3q8/P9TlUP09iQxwM90+Hsii9xyWOtN1TWkhmbu
kDPL/Qi8BvmH9hLazS3bzMJYSnQRPPMUtsn6JFyHnsUk'

      it 'recover' do
        encrypted_private_key_info = Keystores::Jks::EncryptedPrivateKeyInfo.new(:encoded => Base64.decode64(ENCODED_DATA_BASE_64))
        protector = Keystores::Jks::KeyProtector.new('keystores')
        recovered = protector.recover(encrypted_private_key_info)

        expect(recovered).to be_a(OpenSSL::PKey::DSA)
        expect(recovered.params['p'].to_s).to eq(DSA_PRIVATE_KEY_P)
        expect(recovered.params['q'].to_s).to eq(DSA_PRIVATE_KEY_Q)
        expect(recovered.params['g'].to_s).to eq(DSA_PRIVATE_KEY_G)
        expect(recovered.params['priv_key'].to_s).to eq(DSA_PRIVATE_KEY_X)
      end

      it 'protect' do
        # We can't KAT the protect method, since it generates a random salt
        original = OpenSSL::PKey.pkcs8_parse(Base64.decode64(PLAIN_KEY_BASE_64))
        expect(original).to be_a(OpenSSL::PKey::DSA)
        protector = Keystores::Jks::KeyProtector.new('keystores')
        protected = protector.protect(original)

        protector = Keystores::Jks::KeyProtector.new('keystores')
        recovered = protector.recover(Keystores::Jks::EncryptedPrivateKeyInfo.new(:encoded => protected))

        expect(recovered.to_der).to eq(original.to_der)
      end
    end
  end
end

require 'keystores/jks/key_protector'
require 'keystores/jks/encrypted_private_key_info'
require 'base64'
require 'openssl'

# KAT inputs and answers are taken from test/test.jks alias test_private_key_entry
ENCRYPTED_DATA_ASN_1_BASE_64 = 'pAu6N6wKaUj3pJA5LAGKH6RlYfFskU8zpLMb1nCftWZ/OEvEBR4BLWZwFEaZmSdQnPYKVMNIvyxP
D1BJ+tp/5UexxTsmC2uxHm+MOvfn6wAVrst7GAQcehoCwQIG22cykp0HnKzMbXSyuMhLbTZj1mEb
9zm99TyqkwUgr9VzKtaMAKDR/UQXJyzKcpugwpKQAwaq22hEX8UKwlgXvasmPFbYkReKs9H54fPz
lZH3x7GC3gsCuu15dAW6xzfTwGk2YgqrN9M+7sKy0gRXEv1PMNyBg9bDkSM3jHIL5v9Cy9aSPkZJ
FiTWs+eW+WxFrEygiBVT4/Of/haK12/6TCeFPUxYx3KSAN//voZt8c441Y8K6COlw3nYC0ojF280
E6fnObK6bZTQ695MAficLX+wQE5WVQg9WrUmEFMIdz8NQIDUcQyBcVH38ZTiPgEcrOvnzG7T2XKC
UHDVkVopkwdKm+dr8C3bzMJYSnQRPPMUtsn6JFyHnsUk'

ENCODED_DATA_BASE_64 = 'MIIBizAOBgorBgEEASoCEQEBBQAEggF3pAu6N6wKaUj3pJA5LAGKH6RlYfFskU8zpLMb1nCftWZ/
OEvEBR4BLWZwFEaZmSdQnPYKVMNIvyxPD1BJ+tp/5UexxTsmC2uxHm+MOvfn6wAVrst7GAQcehoC
wQIG22cykp0HnKzMbXSyuMhLbTZj1mEb9zm99TyqkwUgr9VzKtaMAKDR/UQXJyzKcpugwpKQAwaq
22hEX8UKwlgXvasmPFbYkReKs9H54fPzlZH3x7GC3gsCuu15dAW6xzfTwGk2YgqrN9M+7sKy0gRX
Ev1PMNyBg9bDkSM3jHIL5v9Cy9aSPkZJFiTWs+eW+WxFrEygiBVT4/Of/haK12/6TCeFPUxYx3KS
AN//voZt8c441Y8K6COlw3nYC0ojF280E6fnObK6bZTQ695MAficLX+wQE5WVQg9WrUmEFMIdz8N
QIDUcQyBcVH38ZTiPgEcrOvnzG7T2XKCUHDVkVopkwdKm+dr8C3bzMJYSnQRPPMUtsn6JFyHnsUk'

ALG_ID = '1.3.6.1.4.1.42.2.17.1.1'

FINAL_DIGEST_KAT_BASE64 = 'LdvMwlhKdBE88xS2yfokXIeexSQ='

# Local pAu6N6wKaUj3pJA5LAGKH6RlYfE=
SALT_KAT_BASE64 = 'pAu6N6wKaUj3pJA5LAGKH6RlYfE='

ENCRYPTED_KEY_KAT_BASE_64 = 'bJFPM6SzG9Zwn7VmfzhLxAUeAS1mcBRGmZknUJz2ClTDSL8sTw9QSfraf+VHscU7JgtrsR5vjDr3
5+sAFa7LexgEHHoaAsECBttnMpKdB5yszG10srjIS202Y9ZhG/c5vfU8qpMFIK/VcyrWjACg0f1E
FycsynKboMKSkAMGqttoRF/FCsJYF72rJjxW2JEXirPR+eHz85WR98exgt4LArrteXQFusc308Bp
NmIKqzfTPu7CstIEVxL9TzDcgYPWw5EjN4xyC+b/QsvWkj5GSRYk1rPnlvlsRaxMoIgVU+Pzn/4W
itdv+kwnhT1MWMdykgDf/76GbfHOONWPCugjpcN52AtKIxdvNBOn5zmyum2U0OveTAH4nC1/sEBO
VlUIPVq1JhBTCHc/DUCA1HEMgXFR9/GU4j4BHKzr58xu09lyglBw1ZFaKZMHSpvna/A='

# Local update * 2: 2jmj7l5rSw0yVb/vlWAYkK/YBwk=
# Local combined XBNOeKayG+bynplgeBLNjMsmBSw=
# Ruby combined XBNOeKayG+bynplgeBLNjMsmBSw=
# Ruby update * 2: XBNOeKayG+bynplgeBLNjMsmBSw=
DIGEST_ROUND_1_KAT = 'XBNOeKayG+bynplgeBLNjMsmBSw='

XOR_KEY_KAT = 'XBNOeKayG+bynplgeBLNjMsmBSxW8hVZmximUGGJWdXePa0FHdAa1dQ2mwKxoHJpGuQvsd1xs7pB
ts1pUPOLWUn/RUeXWju9wy7dAmRWnMnAG+xPMqX8JJ9QA2EKgqecGWqjQpd+MI0XPJF/W/4XF+a8
LHDLDNo9tc2Wa4DweR52h13wXtECASyZ0Emldrp2XZk+C8Pw6ghAv8Z2gMsLldq99mEmsQuFQXnr
lImOoMeLIhvAM1MEoPNdyuZHvF0dfzp/ATQlsp9r7XAsqNTEsEFo3Y7gFJ49HPvCGlxMHAWCmO6X
CmMm7D0EbXFkTtTFXQntc3YgjM3YQl7bdmULRWDXxiD5hWL+WrDY7MOTjw9lK4mkTSXDUImODugf
xtygvoVUfPXMDuW0ax4AryQp5XAdzA9bqxQFCq7/iKr8zCj52zSGxdWD5W/P02d327o='

PLAIN_KEY_KAT = 'MIIBSwIBADCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2
USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4
O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmC
ouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCB
gLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhR
kImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoEFgIUb2aSH/GLWWT2EETZzPzImfyQsEo='

JAVA_ENCODED_KEY = 'MIIBSwIBADCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2
USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4
O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmC
ouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCB
gLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhR
kImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoEFgIUb2aSH/GLWWT2EETZzPzImfyQsEo='

PASSWD_BYTES_KAT = 'AGsAZQB5AHMAdABvAHIAZQBz'

# Local k1U2G/Fgq9bTjDqoW3Yxj98oYdk=
PASSWD_BYTES_DIGEST_KAT = 'k1U2G/Fgq9bTjDqoW3Yxj98oYdk='

SALT_DIGEST_KAT = '51NSA7aXtz0pTwsR4cQM/1H+ui8='

require 'openssl'
require 'base64'

def box(tag, lines)
  lines.unshift "-----BEGIN #{tag}-----"
  lines.push "-----END #{tag}-----"
  lines.join("\n")
end

def der_to_pem(tag, der)
  box tag, Base64.strict_encode64(der).scan(/.{1,64}/)
end

describe Keystores::Jks::KeyProtector do
  it 'KAT recover' do
    encrypted_private_key_info = Keystores::Jks::EncryptedPrivateKeyInfo.new(Base64.decode64(ENCODED_DATA_BASE_64))
    protector = Keystores::Jks::KeyProtector.new('keystores')
    recovered = protector.recover(encrypted_private_key_info)

    expect(recovered).to be_a(OpenSSL::PKey::DSA)
  end
end

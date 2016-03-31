require 'base64'
require 'openssl'
require 'keystores/jks/pkcs8_key'

describe 'openssl PKCS#8 key' do
  context 'KAT' do
    context 'DSA' do

      # Encoded (plain text) DSA key obtained via debugger after decrypting from Java Key Store loaded in JVM
      PLAIN_DSA_KEY_PKCS8_DER = Base64.decode64('MIIBSwIBADCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2
USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4
O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmC
ouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCB
gLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhR
kImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoEFgIUb2aSH/GLWWT2EETZzPzImfyQsEo=')

      it 'encode and decode' do
        dsa_key = OpenSSL::PKey::DSA.new(PLAIN_DSA_KEY_PKCS8_DER)
        pkcs8_encoded_dsa_key = dsa_key.to_pkcs8
        expect(pkcs8_encoded_dsa_key.to_der).to eq(PLAIN_DSA_KEY_PKCS8_DER)
      end
    end

    context 'RSA' do

      # Encoded (plain text) RSA key obtained via debugger after decrypting from Java Key Store loaded in JVM
      PLAIN_RSA_KEY_PKCS8_DER = Base64.decode64('MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC074AEGWayD4HjpiPlncW/UWTm
RT5eVxQTFVM6Yp3H8n3PZrw/diupBIMGxe1FqRY7BeeYuocmeF/W3OohwjlwUQknve2TtZSoeKeZ
SuljhP3tNxOzI7zG9BOtNKLgr/B9sks7zlxv5zWIzjhUN+guLFAP1HHKJDt72wAMsZ+g+HAywlSi
3ZraN44qDZIwSVzYDtT8veSws7p+jAOepb3/bx5xPoeEqkcR6QX1BsL2Q+hhZBjAqqTC4uv0IHD8
NW8mCINqcEuQPZpuuxe9Ov7O9WQJIH3CuLsNPMFIdhXmzD1KSD1ofYzRPZJPdcorsMCEQBP2nLJ5
ygXNNABYSREFAgMBAAECggEAFdMBrPznXzjxoOTsVYj3TkFiG0hk4no8aKTc2iEFCRYdyMOKl1kI
oSVzLID5QrrHfK0Up15waNqCLOeOsi28Qej0Yr/NBVEUslGDXcEkb6Wd/1vyW1xHK/RK30yHDPUL
3A2Cd59HlRPdaDf/oWDw94jOy2oDo69FIYZj9iQCria1Ch2tmVrMb+ieijgJLJh0HG1aKOQmyrHC
GLaUnx8XdHs4en9a9IGrZ1BgU4AEFnpxurVXx1apy6gg1CjHAvVEABsr2F4fmyctVOW/Oal/IHBX
jWbZyBwJeIFvV4YPZTIY2S4llOZdbzdIL4f+UtvxlEWWIHxek6Y1ZHgzVm97wQKBgQDzUyp0Nbyt
PIUxLHIsPnAP2NdDQJkL4VOIZpLsLlwnZrhaC46kUTyTbO+h5BtP1CQCaTCOHRjzpe3S/aWK8lZg
QwnILRj1kXPGUNyqAw4nYWuHTURcjO9WOAPEQxhQhbtfs+TVkiDUQsuEFHIcrRacXiNM84/6aBLv
fng+AvbQMQKBgQC+XFkHBxJtOH498GhphNq8NZuu8Bxv6+OFmSIUXypRiLn5fBH3OBJZCG8vaay7
8z81HMsme9nv/ltBTf71EtU27zLOr27ZFDvnWccbljR1byzKDmUklFK30SUsh8xd70AlRyS3gHrk
e8TRSfAW+dEVaCvrovLXe0u7H39ePo+NFQKBgHHSqJxd+tnK4r9i/DGoL4GqPOBP2ogNKqc23Gmx
MhiYW4p7t4k0GzMXlW1UqFYKdaHPFRCVmfN33i2By6uYu0EievPx7KgLF25gqyi4bymKz+MmCOGG
Z/scDt8DR996/3DAVT52sfa5HDy3172EVnxlKPw5P1Oy1ZDEx3iyqEQxAoGARmBT1aJKsLBzE6ke
oOwqBez3ypwgl0wpSIoNrGRme9BFmTPCXJiRR/MzT98MqkvKsXMcs/ST5QMvb5xLRwWYZ//U087N
91lgsC5jyxIkAMqCT4003WosjqK20Ji/+HZsS5vaujC4vmH3qLxiE8x1/SkPG8WZbAq8O8jwSMJu
ReUCgYBbU7LqUJZ06b+QTHRaVyJKnCpROIP/drEIeBwLj52vuXJcfVNQ1rtnN8jWFQjy52PFU0VK
db5izFmrdwg72M7V5EVQBWvoKq77YQuXCiqVuopQAD5KfzIKyf/Wuz8Pr704wIXlNQWl9As61pSr
ws6f74wy2EZ4nCwQ9u+cKI8x7A==')

      it 'encode and decode' do
        rsa_key = OpenSSL::PKey::RSA.new(PLAIN_RSA_KEY_PKCS8_DER)
        pkcs8_encoded_rsa_key = rsa_key.to_pkcs8
        expect(pkcs8_encoded_rsa_key.to_der).to eq(PLAIN_RSA_KEY_PKCS8_DER)
      end
    end

    context 'EC' do

      PLAIN_EC_KEY_PKCS8_DER = Base64.decode64('MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCAIk25QlC2rUvXohshpJz0w59jVd8M9
oGoeIut84zHLPQ==')

      PLAIN_EC_KEY_OCTET_PARSED = 'CJNuUJQtq1L16IbIaSc9MOfY1XfDPaBqHiLrfOMxyz0='
      PLAIN_EC_KEY_OCTET_JAVA = 'CJNuUJQtq1L16IbIaSc9MOfY1XfDPaBqHiLrfOMxyz0='
      bytes = Base64.decode64(PLAIN_EC_KEY_OCTET_PARSED)
      OpenSSL::BN.new(bytes, 2)

      it 'encode and decode' do
        ec_key = OpenSSL::PKey::EC.new(PLAIN_EC_KEY_PKCS8_DER)
        pkcs8_encoded_ec_key = ec_key.to_pkcs8
        expect(pkcs8_encoded_ec_key.to_der).to eq(PLAIN_EC_KEY_PKCS8_DER)
      end
    end
  end
end

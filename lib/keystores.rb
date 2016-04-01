require 'keystores/java_key_store'

module OpenSSL
  # Alias the key store implementations in the OpenSSL module structure
  class JKS < Keystores::JavaKeystore; end
end

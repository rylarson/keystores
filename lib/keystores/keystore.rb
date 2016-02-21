module Keystores
  class Keystore

    @@registry = {}

    # Get an instance of a key store, given a key store algorithm string
    def self.get_instance(key_store_algorithm)
      @@registry[key_store_algorithm].new
    end

    # Register your key store algorithm
    def self.register_algorithm(algorithm, clazz)
      @@registry[algorithm] = clazz
    end

    # Lists all the alias names of this keystore.
    def aliases

    end

    # Checks if the given alias exists in this keystore.
    def contains_alias(aliaz)

    end

    # Deletes the entry identified by the given alias from this keystore.
    def delete_entry(aliaz)

    end

    # Returns the certificate associated with the given alias.
    def get_certificate(aliaz)

    end

    # Returns the (alias) name of the first keystore entry whose certificate matches the given certificate.
    def get_certificate_alias(certificate)

    end

    # Returns the certificate chain associated with the given alias.
    def get_certificate_chain(aliaz)

    end

    # Returns the key associated with the given alias, using the given password to recover it.
    def get_key(aliaz, password)

    end

    # Returns the type of this keystore.
    def get_type

    end

    # Returns true if the entry identified by the given alias was created by a call to #set_certificate_entry
    def is_certificate_entry(aliaz)

    end

    # Returns true if the entry identified by the given alias was created by a call to #set_key_entry
    def is_key_entry(aliaz)

    end

    # Loads this Keystore from the given path.
    def load(key_store_file, password)

    end

    # Stores this keystore to the given path, and protects its integrity with the given password.
    def store(key_store_file, password)

    end

    # Assigns the given trusted certificate to the given alias.
    def set_certificate_entry(aliaz, certificate)

    end

    # Assigns the given key to the given alias. If password is nil, it is assumed that the key is already protected
    def set_key_entry(aliaz, key, certificate_chain, password = nil)

    end

    # Retrieves the number of entries in this keystore.
    def size

    end
  end
end

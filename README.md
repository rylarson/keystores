# Keystores

This gem provides ruby implementations of different key stores. This was primarily created to provide the ability
to use many of the good Java key stores from ruby.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'keystores'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install keystores

## Usage

The API for this gem is modeled after the Java `KeyStore` class. All of the `KeyStore` implementations provided by this
gem conform to the `Keystores::Keystore` interface.

The certificate and key objects that these keystores return and expect are `OpenSSL::X509::Certificate` and
`OpenSSL::PKey` objects, respectively.

### Supported Key Store types

#### Java Key Store (jks) format

Example usage:

```
require 'keystores/java_keystore`
keystore = Keystores::JavaKeystore.new

# Load can take any IO object, or a path to a file
key_store_password = 'keystores'
keystore.load('/tmp/keystore.jks', key_store_password)

certificate = keystore.get_certificate('my_certificate')
key = keystore.get_key('my_key', key_store_password)
```


## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/keystores.


## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).


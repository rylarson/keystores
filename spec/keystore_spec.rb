require 'spec_helper'
require 'keystores/keystore'

class Keystore1 < Keystores::Keystore;end
class Keystore2 < Keystores::Keystore;end
class Keystore3 < Keystores::Keystore;end

describe Keystores::Keystore do
  it 'can register and retrieve implementations' do
    Keystores::Keystore.register_algorithm('Keystore1', Keystore1)
    Keystores::Keystore.register_algorithm('Keystore2', Keystore2)
    Keystores::Keystore.register_algorithm('Keystore3', Keystore3)

    expect(Keystores::Keystore.get_instance('Keystore1')).to be_a Keystore1
    expect(Keystores::Keystore.get_instance('Keystore2')).to be_a Keystore2
    expect(Keystores::Keystore.get_instance('Keystore3')).to be_a Keystore3
  end
end

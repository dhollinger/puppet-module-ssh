require 'spec_helper'

describe Puppet::Type.type(:ssh_authorized_principal).provider(:parsed) do
  let(:resource) do
    Puppet::Type.type(:ssh_authorized_principal).new({
        :ensure => :present,
        :name   => 'user@domain',
        :target => '/tmp/authorized_principals'
      })
  end
  let(:provider) { resource.provider }

  before :each do
    Facter.stubs(:value).with(:kernel).returns('Linux')
  end

  let(:instance) { provider.class.instances.first }

  describe 'self.prefetch' do
    it 'exists' do
      provider.class.instances
      provider.class.prefetch({})
    end
  end

  describe 'create' do

  end
end
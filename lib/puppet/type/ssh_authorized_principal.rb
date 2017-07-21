Puppet::Type.newtype(:ssh_authorized_principal) do
  @doc = 'Manages SSH authorized principals.'

  ensurable

  newparam(:name, :namevar => true) do
    desc 'Name of the SSH principal to add to the authorized_principals file.'
  end

  newproperty(:user) do
    desc 'The user account in with the SSH principal is placed.'
  end

  newproperty(:target) do
    desc 'The absolute filename in which to store the SSH Principal. This
      property is optional and should only be used in cases where principals
      are stored in a non-default location. Default location is
      `~user/.ssh/authorized_principals`'

    defaultto :absent

    def should
      return super if defined?(@should) and @should[0] != :absent

      begin
        return File.expand_path("~#{user}/.ssh/authorized_principals")
      rescue
        Puppet.debug 'The required user is not yet present on the system'
        return nil
      end
    end

    def insync?(is)
      is == should
    end
  end

  newproperty(:options, :array_matching => :all) do
    desc 'Principal options; see sshd(8) for possible values. Multiple values
      should be specified in an array.'

    defaultto do :absent end

    validate do |value|
      unless value == :absent || value =~ /^[\-a-z0-9A-Z_]+(?:=\".*?\")?$/
        raise Puppet::Error, _("Option %{value} is not valid. A single option must either be of the form 'option' or 'option=\"value\". Multiple options must be provided as an array") % { value: value }
      end
    end
  end

  validate do
    # Go ahead if target is defined
    return if @parameters[:target].shouldorig[0] != :absent

    # Go ahead if user is defined
    return if @parameter[:user].shouldorig[0] != :absent

    # If neither are defined then raise an error
    raise Puppet::Error, _('Attribute "user" or "target" is mandatory')
  end

  # regular expression suitable for use by a ParsedFile based provider
  REGEX = /^(?:(.+)\s+)?(ssh-dss|ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521)\s+([^ ]+)\s*(.*)$/
  def self.keyline_regex
    REGEX
  end

end
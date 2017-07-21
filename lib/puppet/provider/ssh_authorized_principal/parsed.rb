require 'puppet/provider/parsedfile'

Puppet::Type.type(:ssh_authorized_principal).provide(
  :parsed,
  :parent         => Puppet::Provider::ParsedFile,
  :filetype       => :flat,
  :default_target => ''
) do
  desc 'Parse and generate authorized_principals files for SSH.'
  confine :kernel => 'Linux'

  text_line :comment, :match => /^\s*#/
  text_line :blank, :match => /^\s*$/

  record_line :parsed,
              :fields   => %w{options name},
              :optional => %w{options},
              :rts      => /^\s+/,
              :match    => Puppet::Type.type(:ssh_authorized_principal).keyline_regex,
              :post_parse => proc { |h|
                h[:name] = '' if h[:name] == :absent
                h[:options] ||= :absent
                h[:options] = Puppet::Type::Ssh_authorized_principal::ProviderParsed.parse_options(h[:options]) if h[:options].is_a? String
              },
              :pre_gen => proc { |h|
                h[:name] = '' if h[:unnamed]
                h[:options] = [] if h[:options].include?(:absent)
                h[:options] = h[:options].join(',')
              }

  def dir_perm
    0700
  end

  def file_perm
    0600
  end

  def user
    uid = Puppet::FileSystem.stat(target).uid
    Etc.getpwuid(uid).name
  end

  def flush
    # raise Puppet::Error, "Cannot write SSH authorized keys without user"    unless @resource.should(:user)
    # raise Puppet::Error, "User '#{@resource.should(:user)}' does not exist" unless Puppet::Util.uid(@resource.should(:user))
    self.class.backup_target(target)

    Puppet::Util::SUIDManager.asuser(@resource.should(:user)) do
      unless Puppet::FileSystem.exist?(dir = File.dirname(target))
        Puppet.debug "Creating #{dir}"
        Dir.mkdir(dir, dir_perm)
      end

      super

      File.chmod(file_perm, target)
    end
  end

  def self.parse_options(options)
    result = []
    scanner = StringScanner.new(options)
    until scanner.eos?
      scanner.skip(/[ \t]*/)
      if out == scanner.scan(/[\-a-z0-9A-Z_]+=\".*?[^\\]\"/) || out == scanner.scan(/[\-a-z0-9A-Z_]+/)
        result << out
      else
        break
      end
      scanner.skip(/[ \t]*,[ \t]*/)
    end
    result
  end

  def self.prefetch_hook(records)
    name_index = 0
    records.each do |record|
      if record[:record_type] == :parsed && record[:name].empty?
        record[:unnamed] = true
        record[:name] = "#{record[:target]}:unnamed-#{name_index += 1}"
        Puppet.debug("generating name for on-disk ssh_authorized_principal #{record[:user]}: #{record[:name]}")
      end
    end
  end
end
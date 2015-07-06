# https://forge.puppetlabs.com/puppetlabs/firewall
class fw::pre {
  Firewall {
    require => undef,
  }

  # Default firewall rules
  firewall { '000 accept all icmp':
    chain  => 'INPUT',
    proto  => 'icmp',
    action => 'accept',
  }

  # Unlimited lo access
  firewall { '001 accept all to lo interface':
    chain   => 'INPUT',
    proto   => 'all',
    iniface => 'lo',
    action  => 'accept',
  }

  firewall { '002 accept all from lo interface':
    chain    => 'OUTPUT',
    proto    => 'all',
    outiface => 'lo',
    action   => 'accept',
  }

  firewall { '003 reject local traffic not on loopback interface':
    iniface     => '! lo',
    proto       => 'all',
    destination => '127.0.0.1/8',
    action      => 'reject',
  }

  firewall { '004 accept related established rules':
    proto  => 'all',
    state  => ['RELATED', 'ESTABLISHED'],
    action => 'accept',
  }

  # Drop new tcp packet non syn
  firewall { '010 Force TCP SYN':
    proto     => 'tcp',
    tcp_flags => '! FIN,SYN,RST,ACK SYN',
    state     => ['NEW'],
    action    => 'drop',
  }

  # Drop Fragments
  firewall { '011 Drop fragments':
    isfragment => true,
    action     => 'drop',
  }

  # Drop NULL packets
  firewall { '012 Drop NULL packets':
    proto     => 'tcp',
    tcp_flags => 'ALL NONE',
    action    => 'drop',
  }

  # Drop invalid SYN
  firewall { '013 Drop invalid SYN':
    proto     => 'tcp',
    tcp_flags => 'SYN,RST SYN,RST',
    action    => 'drop',
  }

  # Drop invalid SYN
  firewall { '014 Drop invalid SYN':
    proto     => 'tcp',
    tcp_flags => 'SYN,FIN SYN,FIN',
    action    => 'drop',
  }

  # Drop invalid SYN
  firewall { '015 Drop invalid SYN':
    proto     => 'tcp',
    tcp_flags => 'ALL ACK,RST,SYN,FIN',
    action    => 'drop',
  }

  # Drop XMAS packets
  firewall { '016 Drop XMAS packets':
    proto     => 'tcp',
    tcp_flags => 'ALL ALL',
    action    => 'drop',
  }

  # Drop INVALID packets
  firewall { '017 Drop INVALID packets':
    state  => ['INVALID'],
    action => 'drop',
  }

  # Drop Excessive TCP RST Packets
  firewall { '018 Drop Excessive TCP RST Packets':
    proto     => 'tcp',
    tcp_flags => 'RST RST',
    limit     => '2/sec',
    burst     => '2',
    action    => 'drop',
  }

  # DROP SPOOFED PACKETS
  firewall { '030 Drop spoofed packets':
    chain  => 'INPUT',
    source => '169.254.0.0/16',
    action => 'drop',
  }

  firewall { '031 Drop spoofed packets':
    chain  => 'INPUT',
    source => '127.0.0.0/8',
    action => 'drop',
  }

  firewall { '032 Drop spoofed packets':
    chain  => 'INPUT',
    source => '224.0.0.0/4',
    action => 'drop',
  }

  firewall { '033 Drop spoofed packets':
    chain       => 'INPUT',
    destination => '224.0.0.0/4',
    action      => 'drop',
  }

  firewall { '034 Drop spoofed packets':
    chain  => 'INPUT',
    source => '240.0.0.0/5',
    action => 'drop',
  }

  firewall { '035 Drop spoofed packets':
    chain       => 'INPUT',
    destination => '240.0.0.0/5',
    action      => 'drop',
  }

  firewall { '036 Drop spoofed packets':
    chain  => 'INPUT',
    source => '0.0.0.0/8',
    action => 'drop',
  }

  firewall { '037 Drop spoofed packets':
    chain       => 'INPUT',
    destination => '0.0.0.0/8',
    action      => 'drop',
  }

  firewall { '038 Drop spoofed packets':
    chain       => 'INPUT',
    destination => '239.255.255.0/24',
    action      => 'drop',
  }

  firewall { '039 Drop spoofed packets':
    chain       => 'INPUT',
    destination => '255.255.255.255',
    action      => 'drop',
  }

  # extra
  firewall { '200 allow outgoing icmp type 8 (ping)':
    chain  => 'OUTPUT',
    proto  => 'icmp',
    icmp   => 'echo-request',
    action => 'accept',
  }
  
  firewall { '200 allow outgoing dns lookups':
    chain  => 'OUTPUT',
    state  => ['NEW'],
    dport  => '53',
    proto  => 'udp',
    action => 'accept',
  }

  firewall { '200 allow outgoing ntp requests':
    chain  => 'OUTPUT',
    state  => ['NEW'],
    dport  => '123',
    proto  => 'udp',
    action => 'accept',
  }

  firewall { '200 allow outgoing http':
    chain  => 'OUTPUT',
    state  => ['NEW'],
    dport  => ['80', '443'],
    proto  => 'tcp',
    action => 'accept',
  }

}

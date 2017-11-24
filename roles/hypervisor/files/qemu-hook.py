#!/usr/bin/env python

import syslog, sys, argparse, json, glob, os.path, subprocess, os

CHAIN_PREFIX="virt-forward-"

RULE_LOCATIONS = {
  "prerouting": ("nat", "PREROUTING"),
  "forward": ("filter", "FORWARD"),
  "postrouting": ("nat", "POSTROUTING"),
}

class Forwarding(object):
  def __init__(self, config_dir):
    self.COMMENT_MAGIC="5c1eac6b"
    self.config_dir = config_dir

    self.parse_configuration()

  def parse_configuration(self):
    self.domains = {}
    for filename in glob.glob( os.path.join(self.config_dir, "*.conf") ):
      self._parse_file(filename)

  def _parse_file(self, filename):
    with file(filename) as fp:
      config = json.load(fp)
      self.domains[ config["domain"] ] = config

  def set_all_forwardings(self):
    
    # For (mostly) atomic operation, create a temporary chain first
    for name, location in RULE_LOCATIONS.items():
      chainname = "%s-tmp" % name
      self.remove_chain(chainname, location)
      self.delete_chain(chainname, location)
      self.create_chain(chainname, location)
    
    try:
      # Now insert the actual rules
      for domain, config in self.domains.items():
        pubip = config["external_ip"]
        privip = config["internal_ip"]
        for forward in config["forwardings"]:
          proto = forward.get("proto", "tcp")
          privport = forward["dst"]
          pubport = forward.get("src", privport)

          self.add_rule_tmp("prerouting", "-p", proto, "-d", pubip, "--dport", pubport, "-j", "DNAT", "--to", "%s:%s" % (privip, privport) )
          self.add_rule_tmp("forward",    "-p", proto, "-d", privip, "--dport", privport, "-j", "ACCEPT")
        
        self.add_rule_tmp("postrouting", "-p", "tcp", "-s", privip, "-j", "SNAT", "--to", "%s:1024-65535" % pubip)
        self.add_rule_tmp("postrouting", "-p", "udp", "-s", privip, "-j", "SNAT", "--to", "%s:1024-65535" % pubip)

    except:
      # Clear temporary chains
      for name, location in RULE_LOCATIONS.items():
        chainname = "%s-tmp" % name
        self.remove_chain(chainname, location)
        self.delete_chain(chainname, location)
      raise

    # Pivot the chain references
    for name, location in RULE_LOCATIONS.items():
      self.insert_chain("%s-tmp" % name, location)
      self.remove_chain(name, location)
      self.delete_chain(name, location)
      self.rename_chain("%s-tmp" % name, name, location)

  def add_rule_tmp(self, rule_type, *params):
    location = RULE_LOCATIONS[rule_type]
    self.iptables("-t", location[0], "-A", CHAIN_PREFIX+"%s-tmp"%rule_type, *params)

  def delete_chain(self, chainname, location):
    self.iptables_noerror("-t", location[0], "-F", CHAIN_PREFIX+chainname)
    self.iptables_noerror("-t", location[0], "-X", CHAIN_PREFIX+chainname)

  def remove_chain(self, chainname, location):
    self.iptables_noerror("-t", location[0], "-D", location[1], "-j", CHAIN_PREFIX+chainname)

  def create_chain(self, chainname, location):
    self.iptables("-t", location[0], "-N", CHAIN_PREFIX+chainname)

  def insert_chain(self, chainname, location):
    self.iptables("-t", location[0], "-I", location[1], "-j", CHAIN_PREFIX+chainname)

  def rename_chain(self, chainname, new_name, location):
    self.iptables("-t", location[0], "-E", CHAIN_PREFIX+chainname, CHAIN_PREFIX+new_name)

  def iptables(self, *args):
    return self.call_iptables(arguments=args)

  def iptables_noerror(self, *args):
    return self.call_iptables(arguments=args, ignore_errors=True)

  def call_iptables(self, arguments, ignore_errors=False):
    callfunc = subprocess.call if ignore_errors else subprocess.check_call
    stderr = file("/dev/null","w") if ignore_errors else sys.stderr
    return callfunc( ["iptables"] + [unicode(e) for e in arguments], 
        stderr = stderr,
        env={"PATH": os.getenv("PATH", "/bin:/usr/bin") + ":/sbin:/usr/sbin"} )

if __name__ == "__main__":
  syslog.syslog("Called with %r" % sys.argv)

  parser = argparse.ArgumentParser(description='libvirt hook for packet forwarding')
  parser.add_argument('-c', '--configuration-directory', type=str, help='The directory in which to look for the configuration', default='/etc/libvirt/port_forwards')
  parser.add_argument('domain', type=str, help='The name of the object being affected (virtual machine name)')
  parser.add_argument('operation', type=str, help='The operation being performed')
  parser.add_argument('sub_operation', type=str, nargs='?', help='The sub-operation being performed')
  parser.add_argument('extra_argument', type=str, nargs='?', help='An extra argument')

  args = parser.parse_args()

  f = Forwarding(args.configuration_directory)

  ## We just ignore the arguments and do everything every time
  try:
    f.set_all_forwardings()

  except Exception as e:
    syslog.syslog("Exception while executing: %s" % e)

  sys.exit(0)

## I need a plug-in API to modify the inventory after it's loaded
## No such API exists:
##  + inventory scripts/dynamic inventory must create a new inventory
##    from whole cloth and doesn't get a reference to the inventory created
##    by existing plugins.
##  + vars_plugins are only run on demand, and cannot, for example, usefully
##    change group membership
##
## This system monkeypatches a hook into ansible.inventory.manager.InventoryManager
##  and changes the already existing instances of the class on the stack, then
##  refreshes the inventory with the new hook in place.

DEBUG=False

class MyInventoryManager(object):

  def central_services_update_host(self, host):
    data ={}

    g_list = list(host.groups)
    g_list.sort(cmp=group_order)
    if DEBUG: print("LIST NOW %r" % g_list)

    for g in g_list:
      for (k,v) in g.vars.items():
        update_vars(data, k, v)
        if DEBUG: print("DATA %r updated for %r: add %r=%r" % (host,g,k,v))

    for key in host.vars.keys():
      if key in data:
        del data[key]
        if DEBUG: print("DATA %r removing key %r" % (host,key))

    effective_vars = dict(host.vars)
    effective_vars.update(data)

    ### Dynamically create groups and assign host if necessary
    for group in effective_vars.get("groups", []):
      if group not in self.list_groups():
        self.add_group(group)
        self.reconcile_inventory()
      self.groups[group].add_host(host)
      effective_vars.setdefault("group_names", []).append(group)
      self.reconcile_inventory()

    if DEBUG: print("DATA %r now %r" % (host,data))
    for k,v in data.items():
      host.set_variable(k, v)


  def parse_sources(self, *args, **kwargs):
    retval = super(MyInventoryManager, self).parse_sources(*args, **kwargs)
    
    for host in self.get_hosts():
      self.central_services_update_host(host)

    return retval

def group_order(a, b):
  if DEBUG: print("COMPARE %r %r" % (a,b))
  if a in b.child_groups:
    return 1
  elif b in a.parent_groups:
    return 1
  elif a in b.parent_groups:
    return -1
  elif b in a.child_groups:
    return -1

  if DEBUG: print("UHH %r %r" % (a,b))
  return 0

def update_vars(data, key, value):
  key_stem = key.split()[0]
  if key_stem in data and key_stem != key:
    if isinstance(data[key_stem], dict):
      data[key_stem] = dict(data[key_stem], **value)
    elif isinstance(data[key_stem], (list, tuple)):
      data[key_stem] = list(data[key_stem])
      data[key_stem].extend(value)
    else:
      raise TypeError, "Couldn't merge %r into %r" % (key, data)
  else:
    data[key_stem] = value


def install_hook():
  if DEBUG: print("HOOKING")
  from ansible.inventory.manager import InventoryManager as OriginalManager
  class HookedManager(MyInventoryManager, OriginalManager):
    __module__ = OriginalManager.__module__
    __doc__ = OriginalManager.__doc__
  HookedManager.__name__ = OriginalManager.__name__

  from ansible.inventory import manager
  manager.InventoryManager = HookedManager

  ## This HACK HACK HACK works through the stack and live-patches the 
  ##  classes of existing objects.  Ain't Python great?
  import sys
  depth = 1

  while True:
    try:
      frame = sys._getframe(depth)
      depth = depth + 1
    except ValueError:
      break

    for obj in frame.f_locals.values() + frame.f_globals.values():
      if isinstance(obj, OriginalManager) and not isinstance(obj, HookedManager):
        obj.__class__ = HookedManager
        
        # Note: This will cause a double parse
        if DEBUG: print("HOOK INSTALLED")
        obj.refresh_inventory()
install_hook()


## The following is necessary for ansible to not report this
##  'callback_module' as broken. It should be a no-op.
from ansible.plugins.callback import CallbackBase
class CallbackModule(CallbackBase): pass

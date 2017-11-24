def default_hash(data, defaults, key=None):
	"Reverse combine. Returns a copy of data with all keys that are set in defaults but not in data set to the value from defaults."
	if key is None:
		retval = dict( defaults )
		retval.update(data)
	else:
		retval = dict(data)
		retval[key] = dict(defaults)
		retval[key].update(data.get(key, {}))
	return retval

def select_keys(data, keys):
	"Return a copy of data without everything not in keys. If data argument is list, apply to the subelements."
	if isinstance(data, (list, tuple)):
		return [select_keys(e, keys) for e in data]
	else:
		retval = dict()
		for key in set( data.keys() ).intersection( set(keys) ):
			retval[key] = data[key]
		return retval

def relative_dns(data, domain):
	"if data doesn't end with a ., append domain. result is guaranteed to end with a ."
	if len(data) > 0:
		if data[-1] != ".":
			data = data + "." + domain
	else:
		data = domain
	if not data.endswith("."):
		data = data + "."
	return data

def encode_djbdns(data):
	"encodes all non-alphabet characters to octal escapes"
	import string
	return "".join( ( e if e in (string.letters+string.digits) else ("\\%s" % oct(ord(e))[-3:])  ) for e in data )

def ipv6_explode(data):
	"very simple 'decompression' for IPv6 addresses: 2001::1 -> 2001:0000:0000:0000:0000:0000:0000:0001"
	parts = data.split(":")
	retval = []
	for i,p in enumerate(parts):
		if p == "":
			while len(retval) + len(parts) - (i+1) < 8:
				retval.append("0000")
		else:
			retval.append( ("0000"+p)[-4:] )
	return ":".join(retval)

class FilterModule(object):
	'''
	custom jinja2 filters
	'''

	def filters(self):
		return {
			'default_hash': default_hash,
			'select_keys': select_keys,
			'relative_dns': relative_dns,
			'encode_djbdns': encode_djbdns,
			'ipv6_explode': ipv6_explode
		}

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

class FilterModule(object):
	'''
	custom jinja2 filters
	'''

	def filters(self):
		return {
			'default_hash': default_hash,
			'select_keys': select_keys
		}

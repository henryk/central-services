def default_hash(data, defaults):
	"Reverse combine. Returns a copy of data with all keys that are set in defaults but not in data set to the value from defaults."
	retval = dict( defaults )
	retval.update(data)
	return retval

class FilterModule(object):
	'''
	custom jinja2 filters
	'''

	def filters(self):
		return {
			'default_hash': default_hash
		}

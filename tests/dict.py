import collections

IP = 1
SWITCH = 2
PORT = 3
STATE = 4
COUNTER = 5

details = ['srcip', 'switch', 'inport', 'on']

d = collections.defaultdict(list)

for detail in details:
	d['Mac1'].append(detail)


print d
print d.get('Mac1')[0]
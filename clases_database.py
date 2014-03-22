class Database:
    
    def manage(self, action):
    	if(action == 0):
    		self.set_off()
    	elif(action == 1):
    		self.set_on()
    	else:
    		self.save()
    def save(self):
    	print 'Save'
    def set_on(self):
    	print 'Set on'
    def set_off(self):
    	print 'Set off'


x = Database()
x.manage(1)
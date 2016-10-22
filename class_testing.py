# class hai():
# 	def pavan(self):
# 		print ("you got it")


# if __name__=="__main__":
# 	m=hai()
# 	m.pavan()

import os
try:
	k= (os.environ['path'])
except KeyError:
	k="variable does not exist"
finally:
	print(k)
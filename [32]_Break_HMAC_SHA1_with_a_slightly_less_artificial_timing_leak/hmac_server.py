#!/usr/bin/env python
# -*- coding: utf-8 -*-

import lib.sha1_hmac  
import bottle
import time
from bottle import Bottle, run, view, request
from datetime import datetime


def sleep_min(amount):
	'''
		This function check that the webserver sleep the appropriate amount of time.
		Time resolution : 
		  - approx. 1 ms for unix systems
		  - approx. 16 ms for windows
	'''
	start = datetime.now()
	end = start
	delta = end-start
    
	while (delta.seconds + delta.microseconds/1000000.0) < amount:
		time.sleep(0.001)
		end = datetime.now()
		delta = end-start
    


hmac_token = [ "{:02x}".format(c) for c in lib.sha1_hmac.generate_HMAC()]
hmac_len = 20
#print(hmac_token)

app = Bottle()
 
@app.route('/test')
def hello():

	filename = request.params.file
	signature = [ str(request.params.signature[i]) + str(request.params.signature[i + 1]) for i in range(0,len(request.params.signature),2)]

	i = 0
	for hmac_c, sign_c in zip(hmac_token, signature):
		if hmac_c != sign_c:
			break
		#print(hmac_c, sign_c)

		# sleep_min(0.005) 
		time.sleep(0.005) 


		i+=1

	if hmac_len == i:
		return "filename %s valid : %s" % (filename, ":".join(hmac_token))
	else:
		raise bottle.HTTPError(status = 500)

 
run(app, host='localhost', port=8080, reloader=True)
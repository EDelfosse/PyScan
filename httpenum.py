#Web server detection and URL bruteforcer for PyScan
import requests
from multiprocessing.dummy import Pool as  ThreadPool

def scan(RHOST,ports,threads,dictionary):
#########Finds all webservers##################################
	def serverDetection(port):
		req = "http://" + str(RHOST)+":"+str(port)
		try:
			response = requests.get(req,timeout=2)
                	if response.status_code == 200:
                        	return port
			else:
				return()
        	except:
                	return()
###############################################################

	#Sets up threading stuff
	if threads > len(ports):
		threads = len(ports)
	pool = ThreadPool(threads)

	#Runs the serverDetection function against each open port
	results = pool.map(serverDetection,ports)
	pool.close()
	pool.join()
	
	#Sorts the results to only have the open webserver ports left
	results = filter(None, results) #Removes all null entries
	results.sort()
	
	#Output data
	for i in range(0,len(results)):
		print("Web server detected: %s:%d" % (RHOST, results[i]))

#Web server detection and URL bruteforcer for PyScan
import requests
from multiprocessing.dummy import Pool as  ThreadPool

def scan(RHOST,ports,threads,dictionary,extension):
#########Finds all webservers##################################
	def serverDetection(port):
		req = "http://" + str(RHOST)+":"+str(port)
		try:
			response = requests.get(req,timeout=2)
			if response.status_code != 404:
				return port
			else:
				return()
        	except:
                	return()
###############################################################
	currentPortFocus = 0
	extensionFlag = 0
########Bruteforces URL########################################
	def URLBruteforce(url):
		if extensionFlag:
			req = "http://" + str(RHOST)+":" + str(currentPortFocus) + "/" + url+ extension
                else:
			req = "http://" + str(RHOST) +":" + str(currentPortFocus) +  "/" + url +"/"
		try:
                        response = requests.get(req,timeout=2)
                        if response.status_code == 200:
                                print("URL found!: " + req)

                                return req
                        else:
                                return()
                except:
                        return()

###############################################################
	#Sets up threading stuff
	tempThreads = threads
	if tempThreads > len(ports):
		tempThreads = len(ports)
	pool = ThreadPool(tempThreads)
	tempThreads=threads
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
	
	#Start URL bruteforce
	if dictionary != None:
		print("\n[+] Starting URL Bruteforce against found webservers.\n")
		dictionaryFile = open(dictionary, "r")
		urls = dictionaryFile.read().split("\n")

		#Threading stuff
		tempThreads = threads
        	if tempThreads > len(urls):
        	        tempThreads = len(urls)
	        pool = ThreadPool(tempThreads)

		#Brute forces each
		for i in range(0, len(results)):
			currentPortFocus = results[i]
			validUrls = pool.map(URLBruteforce,urls)
				
			#Sorts output
			validUrls = filter(None,validUrls)
			validUrls.sort()
				
			#Outputs info
			print("\nOutputting url's found: \n")
			for i in range(0, len(validUrls)):
				print(validUrls[i])

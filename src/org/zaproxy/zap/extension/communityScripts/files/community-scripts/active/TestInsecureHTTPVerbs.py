"""
Note that new active scripts will initially be disabled
Right click the script in the Scripts tree and select "enable"  
"""

"""
Active Scan Python script to test if the webserver has potentially insecure http methods enabled
Author: http://renouncedthoughts.wordpress.com


Tested to work with some of the online vulnerable applications like:
http://zero.webappsecurity.com
http://testaspnet.vulnweb.com
http://testfire.net/
http://crackme.cenzic.com

and other apps from https://www.owasp.org/index.php/OWASP_Vulnerable_Web_Applications_Directory_Project#tab=On-Line_apps

For some reasons, the order of the array insecureverbs could throw a java.net.SocketTimeoutException, for example with some proxies when TRACE is called just after DELETE
If you encounter such issues, try to change the order on the following line
"""

insecureverbs=["HEAD", "TRACE", "OPTIONS", "PUT", "DELETE", "CONNECT", "DEBUG", "MOVE", "SEARCH", "PATCH", "MKCOL", "COPY", "LOCK", "UNLOCK", "ARBIT", "XXXX", "12AB"]
acceptedhttpstatuscodesforinsecureverbs=[301, 302, 404, 405, 403, 400, 501] # if we get a response code that is not a part of this array, then flag as potentially vulnerable
activevulnerabilitytitle='Potentially Insecure HTTP Verb allowed'
activevulnerabilityfulldescription='Some of the HTTP methods can potentially pose a security risk for a web application, as they allow an attacker to modify the files stored on the web server and, in some scenarios, steal the credentials of legitimate users.' + 'Insecure configuration can possibly lead to web server compromise and website defacement. ' + 'If an application needs one or more of the potentially insecure HTTP methods, such as for REST Web Services (which may require PUT or DELETE), it is important to check that their usage is properly limited to trusted users and safe conditions. ' + 'http://security.stackexchange.com/questions/21413/how-to-exploit-http-methods.'
activevulnerabilitysolution = 'Configure the web server to allow insecure methods like DELETE and PUT only for the relevant resources. ' + 'If your application does not need HTTP methods other than GET and POST, consider disabling the unused HTTP methods.'
printdebugmessages = True
#printdebugmessages= False

def PrintAlerts(sas, msg, uri, insecureverb, responsestatuscode, responsestatusmessage):
	attackevidence = 'VERB: \t' + insecureverb + '\t-- HTTP STATUS CODE: '+ str(responsestatuscode) +' -- \tMESSAGE: ' + responsestatusmessage  + '\t\t-- POTENTIALLY VULNERABLE: YES\n'
	if printdebugmessages:
		print (attackevidence)
	sas.raiseAlert(1, 2, activevulnerabilitytitle, activevulnerabilityfulldescription, uri, 'HTTP VERB', 'ZAP sent an HTTP request with method - ' + insecureverb, '', activevulnerabilitysolution, attackevidence, 0, 0, msg);

	
def ProcessAndPrintAlert(sas, msg, uri, insecureverb):
	if not msg.getResponseHeader().getStatusCode() in acceptedhttpstatuscodesforinsecureverbs:
		PrintAlerts(sas, msg, uri, insecureverb, msg.getResponseHeader().getStatusCode(), msg.getResponseHeader().getReasonPhrase())


def PrepareHttpRequest(msg, insecureverb):
	msg.mutateHttpMethod(insecureverb)
	if insecureverb == "POST" or insecureverb == "PUT":
		msg.setRequestBody("bodytext")
		msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
	if printdebugmessages:
		print('After mutating resulting HTTP VERB: -- \t' + msg.getRequestHeader().getMethod() + '\n')

	
def TestTheURIForInsecureVerbs(sas, msg, uri, insecureverbs):
	for insecureverb in insecureverbs:
		try:
			if printdebugmessages:
				print ('Testing Initiated for the HTTP VERB: -- \t' + insecureverb + '\n')
			msg = msg.cloneRequest();
			PrepareHttpRequest(msg, insecureverb)
			sas.sendAndReceive(msg, False)
			if printdebugmessages:
				print('VERB: \t' + insecureverb + '\t-- STATUS: '+ str(msg.getResponseHeader().getStatusCode()) +' -- \tMESSAGE: ' + msg.getResponseHeader().getReasonPhrase() + '\n')
			ProcessAndPrintAlert(sas, msg, uri, insecureverb)
		except Exception, e:
			print('ERROR For: ' + insecureverb + 'Detail: ' + e.message + '\n')


def scanNode(sas, msg):
	url = msg.getRequestHeader().getURI().toString()
	if printdebugmessages:
    		print('Active scan script called for url = ' + url + '\n')
		print('Testing for insecure verbs against a list of accepted http response status codes for the url = ' + url + '\n')
    	TestTheURIForInsecureVerbs(sas, msg, url, insecureverbs)


def scan(sas, msg, param, value):
    pass
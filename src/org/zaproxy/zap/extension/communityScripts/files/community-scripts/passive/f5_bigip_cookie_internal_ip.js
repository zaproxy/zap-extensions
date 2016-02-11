// Note that new passive scripts will initially be disabled
// Right click the script in the Scripts tree and select "enable"  

// Persistence cookies returned by F5 BigIP devices are used for load balancing 
// and if not properly configured, may reveal IP addresses and ports of internal (RFC1918) components.
// This script passively scans for such cookies being set and attempts to decode them.
// If an analyzed cookie decodes to a RFC1918 IPv4 address then an alert is raised.

// Ref: https://support.f5.com/kb/en-us/solutions/public/6000/900/sol6917.html
// Author: kingthorin+owaspzap@gmail.com
// 20150828 - Initial submission

function scan(ps, msg, src) {
	//Setup some details we will need for alerts later if we find something
	alertRisk = 1
	alertConfidence = 3
	alertTitle = 'Internal IP Exposed via F5 BigIP Persistence Cookie'
	alertDesc = 'The F5 Big-IP Persistence cookie set for this website can be decoded to a specific internal IP and port. An attacker may leverage this information to conduct Social Engineering attacks or other exploits.'
	alertSolution = 'Configure BIG-IP cookie encryption.'
	alertRefs = 'https://support.f5.com/kb/en-us/solutions/public/6000/900/sol6917.html'
	cweId = 311
	wascId = 13

	url = msg.getRequestHeader().getURI().toString();
	//Only check when a cookie is set
	if(msg.getResponseHeader().getHeaders("Set-Cookie")) { 
		cookiesList = msg.getResponseHeader().getHttpCookies(); //Set-Cookie in Response
		cookiesList.addAll(msg.getRequestHeader().getHttpCookies()); //Cookie in Request
		cookiesArr  = cookiesList.toArray();
	
		for (idx in cookiesArr) {
			cookieName=cookiesArr[idx].getName();
			cookieValue=cookiesArr[idx].getValue();
			if(cookieName.toLowerCase().contains("bigip") &&
			  !cookieValue.toLowerCase().contains("deleted")) {
				cookieChunks = cookieValue.split("\\."); //i.e.: 3860990474.36895.0000
				//Decode IP
				try {
					theIP=decodeIP(cookieChunks[0]);
				} catch (e) {
					return //Something went wrong
				}
				//Decode Port
				thePort=decodePort(cookieChunks[1]);

				if(isIPv4Local(theIP)) { //RFC1918
					decodedValue=theIP+':'+thePort;
					alertOtherInfo=cookieValue+" decoded to "+decodedValue;
					//ps.raiseAlert(risk, confidence, title, description, url, param, attack, otherinfo, solution, evidence, cweId, wascId, msg);
					ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDesc, url, 
						cookieName, '', alertOtherInfo, alertSolution+'\n'+alertRefs, 
						cookieValue, cweId, wascId, msg);
				} else { //Not what we're looking for
					return 
				}
			}
		}
	}
}

function decodeIP(ipChunk) {
	backwardIpHex = java.net.InetAddress.getByName(ipChunk);
	backwardAddress = backwardIpHex.getHostAddress();
	ipPieces = backwardAddress.split("\\.");
	theIP = ipPieces[3]+'.'+ipPieces[2]+'.'+ipPieces[1]+'.'+ipPieces[0]
	return(theIP)
}

function isIPv4Local(ip) {
	try {
		if(java.net.Inet4Address.getByName(ip).isSiteLocalAddress())
			return true //RFC1918 and IPv4
	} catch (e) {
		return false //Not IPv4
	}
	return false //Not RFC1918
}
	

function decodePort(portChunk) {
	backwardPortHex = java.lang.Integer.toHexString(java.lang.Integer.parseInt(portChunk));
	assembledPortHex = backwardPortHex.substring(2,4)+backwardPortHex.substring(0,2)
	thePort = java.lang.Integer.parseInt(assembledPortHex, 16);
	return(thePort)
}

// TODO List
//Handle IPv4 pool members in non-default route domains
//Handle IPv6 variants

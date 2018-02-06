// RFC1918 internal IP Finder by freakyclown@gmail.com

function scan(ps, msg, src) {
    url = msg.getRequestHeader().getURI().toString();
    alertRisk = 2
    alertReliability = 2
    alertTitle = "Private IP address in Body(script)"
    alertDesc = "A private IP such as 10.x.x.x, 172.x.x.x, 192.168.x.x or IPV6 fe00:: has been found in the HTTP response body.  This information might be helpful for further attacks targeting internal systems. "
    alertSolution = "Remove the private IP address from the HTTP response body.  For comments, use JSP/ASP comment instead of HTML/JavaScript comment which can be seen by client browsers."

    cweId = 0
    wascId = 0
    // regex must appear within /( and )/g
    re = /((172\.\d{1,3}\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3})|(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|([fF][eE][89aAbBcCdDeEfF]::))/g


    // you can tell the user in the console we are doing stuff by uncommenting the line below
    //print('Finding IPs Under: ' + url);

    // lets check its not one of the files types that are never likely to contain stuff, like pngs and jpegs
    contenttype = msg.getResponseHeader().getHeader("Content-Type")
    unwantedfiletypes = ['image/png', 'image/jpeg','image/gif','application/x-shockwave-flash']
	
	if (unwantedfiletypes.indexOf(""+contenttype) >= 0) {
		// if we find one of the unwanted headers quit this scan, this saves time and reduces false positives
    		return
	}else{
        body = msg.getResponseBody().toString()

        if (re.test(body)) {
            re.lastIndex = 0 // After testing reset index
            // Look for IP addresses
            var foundIP = []
            while (comm = re.exec(body)) {
                foundIP.push(comm[0]);
            }
            ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDesc, url, '', '', foundIP.toString(), alertSolution, '', cweId, wascId, msg);
        }

    }
}

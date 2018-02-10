// Email finder by freakyclown@gmail.com
// Based on:
// PassiveHTMLCommentFinder.js
// kingthorin+owaspzap@gmail.com
// 20150106 - Updated by kingthorin+owaspzap@gmail.com to handle addresses (such as gmail) with alias portion:
//     https://support.google.com/mail/answer/12096?hl=en
//     https://regex101.com/r/sH4vC0/2

function scan(ps, msg, src) {
    // first lets set up some details incase we find an email, these will populate the alert later
    alertRisk = 0
    alertReliability = 3
    alertTitle = 'Email addresses (script)'
    alertDesc = 'Email addresses were found'
    alertSolution = 'Remove emails that are not public'
    cweId = 0
    wascId = 0

	// lets build a regular expression that can find email addresses
	// the regex must appear within /( and )/g
    re = /([a-zA-Z0-9.#?$*_\+-]+@[a-zA-Z0-9.#?$*_-]+.[a-zA-Z0-9.-]+)/g

	// we need to set the url variable to the request or we cant track the alert later
    url = msg.getRequestHeader().getURI().toString();

	// lets check its not one of the files types that are never likely to contain stuff, like pngs and jpegs
     contenttype = msg.getResponseHeader().getHeader("Content-Type")
	unwantedfiletypes = ['image/png', 'image/jpeg','image/gif','application/x-shockwave-flash','application/pdf']
	
	if (unwantedfiletypes.indexOf(""+contenttype) >= 0) {
		// if we find one of the unwanted headers quit this scan, this saves time and reduces false positives
    		return
	}else{
	// now lets run our regex against the body response
        body = msg.getResponseBody().toString()
        if (re.test(body)) {
            re.lastIndex = 0 // After testing reset index
            // Look for email addresses
            var foundEmail = []
            while (comm = re.exec(body)) {
                foundEmail.push(comm[0]);
            }
		  // woohoo we found an email lets make an alert for it
            ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDesc, url, '', '', foundEmail.toString(), alertSolution, '', cweId, wascId, msg);
        }
    }
}

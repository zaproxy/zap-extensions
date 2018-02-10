// The scan function will be called for request/response made via ZAP, excluding some of the automated tools
// Passive scan rules should not make any requests 

// Note that new passive scripts will initially be disabled
// Right click the script in the Scripts tree and select "enable"  

// PassiveHTMLCommentFinder.js
// kingthorin+owaspzap@gmail.com

// References:
// RegEx Testing: http://regex101.com/r/tX1hS1
// Initial discussion: https://groups.google.com/forum/#!topic/zaproxy-develop/t-1-yI7iErw
// RegEx adapted from work by Stephen Ostermiller: http://ostermiller.org/findhtmlcomment.html
// Tweak to RegEx provided by thc202

// NOTE: Designed to work with 2.2 Weekly build version D-2014-03-10 or stable builds at or above v2.3
// NOTE: This script ONLY finds HTML comments. It DOES NOT find JavaScript or other comments.
// NOTE: This script will only find HTML comments in content which passes through ZAP. 
//		Therefore if you browser is caching you may not see something you expect to.

function scan(ps, msg, src) {
    // Both can be true, just know that you'll see duplication.
    RESULT_PER_FINDING = new Boolean(0) // If you want to see results on a per comment basis (i.e.: A single URL may be listed more than once), set this to true (1)
    RESULT_PER_URL = new Boolean(1) // If you want to see results on a per URL basis (i.e.: all comments for a single URL will be grouped together), set this to true (1)
	
    // lets set up some details we will need for alerts later if we find some comments
    alertRisk = 0
    alertReliability = 2
    alertTitle = 'Information Exposure Through HTML Comments (script)'
    alertDesc = 'While adding general comments is very useful, \
some programmers tend to leave important data, such as: filenames related to the web application, old links \
or links which were not meant to be browsed by users, old code fragments, etc.'
    alertSolution = 'Remove comments which have sensitive information about the design/implementation \
of the application. Some of the comments may be exposed to the user and affect the security posture of the \
application.'
    cweId = 615
    wascId = 13
    url = msg.getRequestHeader().getURI().toString();

	// this is a rough regular expression to find HTML comments
	// regex needs to be inside /( and )/g to work
    re = /(\<![\s]*--[\-!@#$%^&*:;ºª.,"'(){}\w\s\/\\[\]]*--[\s]*\>)/g

    // lets check its not one of the files types that are never likely to contain stuff, like pngs and jpegs
    contenttype = msg.getResponseHeader().getHeader("Content-Type")
    unwantedfiletypes = ['image/png', 'image/jpeg','image/gif','application/x-shockwave-flash']
	
	if (unwantedfiletypes.indexOf(""+contenttype) >= 0) {
		// if we find one of the unwanted headers quit this scan, this saves time and reduces false positives
    		return
	}else{
        body = msg.getResponseBody().toString()
        if (re.test(body)) {
            re.lastIndex = 0
            var foundComments = []
            var counter=0
            while (comm = re.exec(body)) {
                if (RESULT_PER_FINDING == true) {
                    counter = counter+1;
                    //fakeparam+counter gives us parameter differientiation per comment alert (RESULT_PER_FINDING)
                    ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDesc, url, 'fakeparam'+counter, '', comm[0], alertSolution,'' , cweId, wascId, msg);
                }
                foundComments.push(comm[0]);
            }
            if (RESULT_PER_URL == true) 
            {
                ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDesc, url, '', '', foundComments.toString(), alertSolution,'' , cweId, wascId, msg);
            }
        }
    }
}

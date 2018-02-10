// RPO (Relative Path Overwrite) Finder by freakyclown@gmail.com
// influenced on burp-suites PRSSI scanner
// for more info see http://www.thespanner.co.uk/2014/03/21/rpo/
// *WARNING* this is a Beta version of this detection and may give many false positives!

function scan(ps, msg, src) {
    url = msg.getRequestHeader().getURI().toString();
    alertRisk = 2
    alertReliability = 2
    alertTitle = "Potential Relative Path Overwrite - RPO(beta script)"
    alertDesc = "Potential RPO (Relative Path Overwrite) found "
    alertSolution = "Make sure all style sheets are refered by full paths rather than relative paths."

    cweId = 0
    wascId = 0
    // regex must appear within /( and )/g
    re = /(href\=\"((?!\/|http|www)).*\.css\")/g

    // lets check its not one of the files types that are never likely to contain stuff, like pngs and jpegs
    contenttype = msg.getResponseHeader().getHeader("Content-Type")
    unwantedfiletypes = ['image/png', 'image/jpeg','image/gif','application/x-shockwave-flash','application/pdf']
	
	if (unwantedfiletypes.indexOf(""+contenttype) >= 0) {
		// if we find one of the unwanted headers quit this scan, this saves time and reduces false positives
    		return
	}else{
        body = msg.getResponseBody().toString()

        if (re.test(body)) {
            re.lastIndex = 0 // After testing reset index
            // Look for RPO
            var foundRPO = []
            while (comm = re.exec(body)) {
                foundRPO.push(comm[0]);
            }
            ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDesc, url, '', '', foundRPO.toString(), alertSolution, '', cweId, wascId, msg);
        }

    }
}

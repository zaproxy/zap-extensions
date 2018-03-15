// Raises a High alert if URL parameters or forms are detected.
// This script is only intended to be used on sites that are believed to be static. 

// Note that new passive scripts will initially be disabled
// Right click the script in the Scripts tree and select "enable"  

/**
 * Passively scans an HTTP message. The scan function will be called for 
 * request/response made via ZAP, actual messages depend on the function
 * "appliesToHistoryType", defined below.
 * 
 * @param ps - the PassiveScan parent object that will do all the core interface tasks 
 *     (i.e.: providing access to Threshold settings, raising alerts, etc.). 
 *     This is an ScriptsPassiveScanner object.
 * @param msg - the HTTP Message being scanned. This is an HttpMessage object.
 * @param src - the Jericho Source representation of the message being scanned.
 */
function scan(ps, msg, src) {
	// Test the request and/or response here
	if (msg.getRequestHeader().getURI().getEscapedQuery() != null) {
		// raiseAlert(risk, int confidence, String name, String description, String uri, 
		//		String param, String attack, String otherInfo, String solution, String evidence, 
		//		int cweId, int wascId, HttpMessage msg)
		// risk: 0: info, 1: low, 2: medium, 3: high
		// confidence: 0: falsePositive, 1: low, 2: medium, 3: high, 4: confirmed
		ps.raiseAlert(3, 2, 'Non static site (query present)', 
			'A query string has been detected in one of the sites URLs. This indicates that this might well not be a static site', 
			msg.getRequestHeader().getURI().toString(), 
			'', '', '', 
			'If this is not a static site then ignore or disable this script', 
			msg.getRequestHeader().getURI().getEscapedQuery(), 0, 0, msg);
	}
	if (src != null && ! src.getFormFields().isEmpty()) {
		// There are form fields
		ps.raiseAlert(3, 2, 'Non static site (form present)', 
			'One or more forms have been detected in the response. This indicates that this might well not be a static site', 
			msg.getRequestHeader().getURI().toString(), 
			'', '', '', 
			'If this is not a static site then ignore or disable this script', 
			src.getFormFields().toString(), 0, 0, msg);
	}
}

/**
 * Tells whether or not the scanner applies to the given history type.
 *
 * @param {Number} historyType - The ID of the history type of the message to be scanned.
 * @return {boolean} Whether or not the message with the given type should be scanned by this scanner.
 */
function appliesToHistoryType(historyType) {
	// For example, to just scan spider messages:
	// return historyType == org.parosproxy.paros.model.HistoryReference.TYPE_SPIDER;

	// Default behaviour scans default types.
	return org.zaproxy.zap.extension.pscan.PluginPassiveScanner.getDefaultHistoryTypes().contains(historyType);
}
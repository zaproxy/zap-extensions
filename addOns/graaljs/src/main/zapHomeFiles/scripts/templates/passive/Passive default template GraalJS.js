// Passive scan rules should not make any requests 

// Note that new passive scripts will initially be disabled
// Right click the script in the Scripts tree and select "enable"  

var PluginPassiveScanner = Java.type("org.zaproxy.zap.extension.pscan.PluginPassiveScanner");

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
	if (true) {	// Change to a test which detects the vulnerability
		// risk: 0: info, 1: low, 2: medium, 3: high
		// confidence: 0: falsePositive, 1: low, 2: medium, 3: high, 4: confirmed
		ps.newAlert()
			.setRisk(1)
			.setConfidence(1)
			.setName('Passive Vulnerability title')
			.setDescription('Full description')
			.setParam('The param')
			.setEvidence('Evidence')
			.setOtherInfo('Any other info')
			.setSolution('The solution')
			.setReference('References')
			.setCweId(0)
			.setWascId(0)
			.raise();
		
		//addTag(String tag)
		ps.addTag('tag')			
	}
	
	// Raise less reliable alert (that is, prone to false positives) when in LOW alert threshold
	// Expected values: "LOW", "MEDIUM", "HIGH"
	if (ps.getAlertThreshold() == "LOW") {
		// ...
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
	return PluginPassiveScanner.getDefaultHistoryTypes().contains(historyType);
}
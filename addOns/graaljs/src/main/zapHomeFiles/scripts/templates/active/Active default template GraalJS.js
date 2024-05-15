// Note that new active scripts will initially be disabled
// Right click the script in the Scripts tree and select "enable"  

const ScanRuleMetadata = Java.type("org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata");

function getMetadata() {
	return ScanRuleMetadata.fromYaml(`
id: 12345
name: Active Vulnerability Title
description: Full description
solution: The solution
references:
  - Reference 1
  - Reference 2
category: INJECTION  # info_gather, browser, server, misc, injection
risk: INFO  # info, low, medium, high
confidence: LOW  # false_positive, low, medium, high, user_confirmed
cweId: 0
wascId: 0
alertTags:
  name1: value1
  name2: value2
otherInfo: Any other Info
status: alpha
`);
}

/**
 * Scans a "node", i.e. an individual entry in the Sites Tree.
 * The scanNode function will typically be called once for every page. 
 * 
 * @param as - the ActiveScan parent object that will do all the core interface tasks 
 *     (i.e.: sending and receiving messages, providing access to Strength and Threshold settings,
 *     raising alerts, etc.). This is an ActiveScriptHelper object.
 * @param msg - the HTTP Message being scanned. This is an HttpMessage object.
 */
function scanNode(as, msg) {
	// Debugging can be done using println like this
	print('scan called for url=' + msg.getRequestHeader().getURI().toString());

	// Copy requests before reusing them
	msg = msg.cloneRequest();
	
	// sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
	as.sendAndReceive(msg, false, false);

	// Test the responses and raise alerts as below

	// Check if the scan was stopped before performing lengthy tasks
	if (as.isStop()) {
		return
	}
	// Do lengthy task...
	
	// Raise less reliable alert (that is, prone to false positives) when in LOW alert threshold
	// Expected values: "LOW", "MEDIUM", "HIGH"
	if (as.getAlertThreshold() == "LOW") {
		// ...
	}
	
	// Do more tests in HIGH attack strength
	// Expected values: "LOW", "MEDIUM", "HIGH", "INSANE"
	if (as.getAttackStrength() == "HIGH") {
		// ...
	}
}

/**
 * Scans a specific parameter in an HTTP message.
 * The scan function will typically be called for every parameter in every URL and Form for every page.
 * 
 * @param as - the ActiveScan parent object that will do all the core interface tasks 
 *     (i.e.: sending and receiving messages, providing access to Strength and Threshold settings,
 *     raising alerts, etc.). This is an ActiveScriptHelper object.
 * @param msg - the HTTP Message being scanned. This is an HttpMessage object.
 * @param {string} param - the name of the parameter being manipulated for this test/scan.
 * @param {string} value - the original parameter value.
 */
function scan(as, msg, param, value) {
	// Debugging can be done using println like this
	print('scan called for url=' + msg.getRequestHeader().getURI().toString() + 
		' param=' + param + ' value=' + value);
	
	// Copy requests before reusing them
	msg = msg.cloneRequest();
	
	// setParam (message, parameterName, newValue)
	as.setParam(msg, param, 'Your attack');
	
	// sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
	as.sendAndReceive(msg, false, false);
	
	// Test the response here, and make other requests as required
	if (true) {	// Change to a test which detects the vulnerability
		as.newAlert()
			.setParam(param)
			.setAttack('Your attack')
			.setEvidence('Evidence')
			.setMessage(msg)
			.raise();
	}
}


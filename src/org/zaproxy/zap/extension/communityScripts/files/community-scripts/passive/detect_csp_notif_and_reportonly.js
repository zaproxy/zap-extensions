/*
Script to detect if the Content-Security-Policy policies defined for the current site:
- Send notifications about violations (some kind of monitoring),
- Behave into "report-only" mode (no blocking, only report violations).

These informations are interesting from an attacker/researcher point of view because it indicates to him:
1) His input validation probing tentatives will be potentially quickly detected (depending on the monitoring level by site owner),
2) The CSP policies in place will not block the exploitation if a vulnerability is found into input validation,
3) Perhaps the endpoint receiving notifications is vulnerable to some injection.

Links:
- http://content-security-policy.com
- http://www.html5rocks.com/en/tutorials/security/content-security-policy
- http://www.html5rocks.com/en/tutorials/security/content-security-policy/#reporting

Author:
dominique.righetto@gmail.com
*/

var Locale = Java.type("java.util.Locale");

function extractUrl(cspPolicies, cspReportInstruction){
	//Extract the URL to which any CSP violations are reported
	//In CSP specification, policies are separated by ';'
	if(cspPolicies.indexOf(cspReportInstruction) != -1){
		var startPosition = cspPolicies.search(cspReportInstruction);
		var tmp = cspPolicies.substring(startPosition);
		var endPosition = tmp.indexOf(";");
		if(endPosition != -1){
			var reportUrl = tmp.substring(0, endPosition);	
		}else{
			var reportUrl = tmp;
		}
		return reportUrl.replace(cspReportInstruction,"").trim();
	}else{
		return null;
	}
}

function scan(ps, msg, src) {
	//Docs on alert raising function:
	// raiseAlert(risk, int confidence, String name, String description, String uri, 
	//		String param, String attack, String otherInfo, String solution, String evidence, 
	//		int cweId, int wascId, HttpMessage msg)
	// risk: 0: info, 1: low, 2: medium, 3: high
	// confidence: 0: falsePositive, 1: low, 2: medium, 3: high, 4: confirmed

	//Common variables
	var cweId = 200; 
	var wascId = 13;
	var url = msg.getRequestHeader().getURI().toString();
	var cspHeaderNames = ["Content-Security-Policy", "X-Content-Security-Policy", "X-Webkit-CSP", "Content-Security-Policy-Report-Only"];
	var cspReportInstruction = "report-uri";

	//Response headers collection
	var responseHeaders = msg.getResponseHeader();

	//Detect and analyze presence of the CSP headers
	for(var i = 0 ; i < cspHeaderNames.length ; i++){
		var headerName = cspHeaderNames[i];
		if(responseHeaders.getHeaders(headerName)){
			//Check if the header values (policies) contains the CSP reporting instruction
			var headerValues = responseHeaders.getHeaders(headerName).toArray();
			for(var j = 0 ; j < headerValues.length ; j++){
				var cspPolicies = headerValues[j].toLowerCase(Locale.ROOT);
				//Extract the URL to which any CSP violations are reported if specified
				var reportUrl = extractUrl(cspPolicies, cspReportInstruction);
				if(reportUrl != null){
					//Raise info alert
					var cspWorkingMode = (headerName.toLowerCase(Locale.ROOT).indexOf("-report-only") == -1) ? "BLOCKING" : "REPORTING";
					var description = "The current site CSP policies defined by HTTP response header '" + headerName + "' (behaving in " + cspWorkingMode + " mode) report violation to '" + reportUrl + "'.";
					var infoLinkRef = "https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Using_CSP_violation_reports";
					var solution = "Site owner will be notified at each policies violations, so, start by analyzing if a real monitoring of the notifications is in place before to use fuzzing or to be more aggressive.";
					ps.raiseAlert(0, 3, "Content Security Policy violations reporting enabled", description, url, "HTTP response header '" + headerName + "'", "", infoLinkRef, solution, headerValues[j], cweId, wascId, msg);
				}
			}
		}
	}
}

/*
Script to detect if the site use the protection bring by the "SameSite" cookie attribute.

Knowing that point is interesting because the goal of this attribute is to mitigate CSRF attack.

Links:
- https://chloe.re/2016/04/13/goodbye-csrf-samesite-to-the-rescue
- https://tools.ietf.org/html/draft-west-first-party-cookies
- https://www.chromestatus.com/feature/4672634709082112

Author:
dominique.righetto@gmail.com
*/

var Locale = Java.type("java.util.Locale");

function scan(ps, msg, src) {
	//Docs on alert raising function:
	// raiseAlert(risk, int confidence, String name, String description, String uri, 
	//		String param, String attack, String otherInfo, String solution, String evidence, 
	//		int cweId, int wascId, HttpMessage msg)
	// risk: 0: info, 1: low, 2: medium, 3: high
	// confidence: 0: falsePositive, 1: low, 2: medium, 3: high, 4: confirmed

	//Common variables
	var cweId = 352;
	var wascId = 9;
	var url = msg.getRequestHeader().getURI().toString();
	var cookieHeaderNames = ["Set-Cookie", "Set-Cookie2"];
	var cookieSameSiteAttributeNameLower = "samesite";

	//Response headers collection
	var responseHeaders = msg.getResponseHeader();

	//Detect and analyze presence of the cookie headers
	for(var i = 0 ; i < cookieHeaderNames.length ; i++){
		var headerName = cookieHeaderNames[i];
		if(responseHeaders.getHeaders(headerName)){
			//Check if the cookie header values contains the SameSite attribute
			var headerValues = responseHeaders.getHeaders(headerName).toArray();
			for(var j = 0 ; j < headerValues.length ; j++){
				var cookieAttributes = headerValues[j].split(";");
				//Inspect each attribute in order to avoid false-positive spot
				//by simply searching "samesite=" on the whole cookie header value...
				for(var k = 0 ; k < cookieAttributes.length ; k++){
					var parts = cookieAttributes[k].split("=");
					if(parts[0].trim().toLowerCase(Locale.ROOT) == cookieSameSiteAttributeNameLower){
						//Raise info alert
						var sameSiteAttrValue = parts[1].trim();
						var cookieName = cookieAttributes[0].split("=")[0].trim();
						var description = "The current site use the 'SameSite' cookie attribute protection on cookie named '" + cookieName + "', value is set to '" + sameSiteAttrValue + "' protection level.";
						var infoLinkRef = "https://tools.ietf.org/html/draft-west-first-party-cookies\nhttps://chloe.re/2016/04/13/goodbye-csrf-samesite-to-the-rescue";
						var solution = "CSRF possible vulnerabilities presents on the site will be mitigated depending on the browser used by the user (browser defines the support level for this cookie attribute).";
						ps.raiseAlert(0, 3, "SameSite cookie attribute protection used", description, url, "Cookie named: '" + cookieName + "'", "", infoLinkRef, solution, sameSiteAttrValue, cweId, wascId, msg);
						break;
					}
				}
			}
		}
	}
}
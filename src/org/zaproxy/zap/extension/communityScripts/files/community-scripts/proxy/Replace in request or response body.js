// Replace strings in the request and/or response body
// Change the script for the strings you want to replace.
//
// The proxyRequest and proxyResponse functions will be called for all requests  and responses made via ZAP, 
// excluding some of the automated tools
// If they return 'false' then the corresponding request / response will be dropped. 
// You can use msg.setForceIntercept(true) in either method to force a break point

// Note that new proxy scripts will initially be disabled
// Right click the script in the Scripts tree and select "enable"  

// The following handles differences in printing between Java 7's Rhino JS engine
// and Java 8's Nashorn JS engine
if (typeof println == 'undefined') this.println = print;

/**
 * This function allows interaction with proxy requests (i.e.: outbound from the browser/client to the server).
 * 
 * @param msg - the HTTP request being proxied. This is an HttpMessage object.
 */
function proxyRequest(msg) {
	println('proxyRequest called for url=' + msg.getRequestHeader().getURI().toString())
	// Remove the '(?i)' for a case exact match
	var req_str_to_change = "(?i)change from this"
	var req_str_to_replace = "changed to this"
	msg.setRequestBody(msg.getRequestBody().toString().replaceAll(req_str_to_change, req_str_to_replace))
	// Update the content length in the header as this may have been changed
	msg.getRequestHeader().setContentLength(msg.getRequestBody().length());

	return true
}

/**
 * This function allows interaction with proxy responses (i.e.: inbound from the server to the browser/client).
 * 
 * @param msg - the HTTP response being proxied. This is an HttpMessage object.
 */
function proxyResponse(msg) {
	println('proxyResponse called for url=' + msg.getRequestHeader().getURI().toString())
	// Remove the '(?i)' for a case exact match
	var req_str_to_change = "(?i)change from this"
	var req_str_to_replace = "changed to this"
	msg.setResponseBody(msg.getResponseBody().toString().replaceAll(req_str_to_change, req_str_to_replace))
	// Update the content length in the header as this may have been changed
	msg.getResponseHeader().setContentLength(msg.getResponseBody().length());

	return true
}

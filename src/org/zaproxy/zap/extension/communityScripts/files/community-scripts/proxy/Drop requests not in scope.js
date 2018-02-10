// This script drops ALL requests that are out of scope

function proxyRequest(msg) {

	// Change this test to match whatever requests you want to fake
	if (!msg.isInScope()) {
		msg.setResponseBody("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2//EN\">\n" +
			"<html><head></head><body><h1>403 Forbidden</h1>\n" +
			"Out of scope request blocked by ZAP script 'Drop requests not in scope.js'\n" +
			"</body></html>");
		msg.setResponseHeader("HTTP/1.1 403 Forbidden\r\n" +
			"Content-Type: text/html; charset=UTF-8");
		msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
	}
	return true
}

function proxyResponse(msg) {
	// Dont need to do anything here
	return true
}


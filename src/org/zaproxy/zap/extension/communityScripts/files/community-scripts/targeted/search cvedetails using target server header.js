// Captures Server header from the application response and searches cvedetails.com for known target server vulnerabilities.


function invokeWith(msg) {

		header = msg.getResponseHeader().getHeader("Server")
		if (header != null) {
		org.zaproxy.zap.utils.DesktopUtils.openUrlInBrowser(
		"http://www.cvedetails.com/google-search-results.php?q=" + encodeURIComponent(header) + "&sa=Search");
		}
		
}

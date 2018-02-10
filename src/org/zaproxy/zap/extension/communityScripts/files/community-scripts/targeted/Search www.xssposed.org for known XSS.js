// Searches www.xssposed.org for known XSS vulnerabilities.
// This script just launches your default browser to perform the search.

function invokeWith(msg) {
	host = msg.getRequestHeader().getURI().getHost(); 

	org.zaproxy.zap.utils.DesktopUtils.openUrlInBrowser(
		"https://www.xssposed.org/search/?search=" + host + "&type=host");
}

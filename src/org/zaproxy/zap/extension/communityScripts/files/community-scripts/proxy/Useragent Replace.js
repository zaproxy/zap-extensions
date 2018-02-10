// This script allows you to replace your browsers User-Agent string easily
// Just edit it to use one of the example ones or replace them with one of your own

// The proxyRequest and proxyResponse functions will be called for all requests  and responses made via ZAP, 
// excluding some of the automated tools
// If they return 'false' then the corresponding request / response will be dropped. 
// You can use msg.setForceIntercept(true) in either method to force a break point

// Note that new proxy scripts will initially be disabled
// Right click the script in the Scripts tree and select "enable"  

function proxyRequest(msg) {
	var ua
	// Uncomment the User Agent line you want to use and leave the rest commented out

	// Mozilla Firefox Linux 64-bit
	ua = 'Mozilla/5.0 (X11; Linux i686 on x86_64; rv:28.0) Gecko/20100101 Firefox/28.0'

	// Chrome 33.0 Win7 64-bit
	// ua = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/33.0.1750.154 Safari/537.36'

	// Safari 7.0 MacOSX
	// ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.74.9 (KHTML, like Gecko) Version/7.0.2 Safari/537.74.9'

	// IE 11.0 Win7 64-bit
	// ua = 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'

	msg.getRequestHeader().setHeader('User-Agent', ua)

	return true
}

function proxyResponse(msg) {
	// Leave the response alone
	return true
}

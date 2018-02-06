// This script was lazily crafted by Anthony Cozamanis, kurobeats@yahoo.co.jp

function proxyRequest(msg) {
	var ua
	ua = 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'
	msg.getRequestHeader().setHeader('User-Agent', ua)
	return true
}

function proxyResponse(msg) {
	// Leave the response alone
	return true
}

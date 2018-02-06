// This script was lazily crafted by Anthony Cozamanis, kurobeats@yahoo.co.jp

function proxyRequest(msg) {
	var ua
	ua = 'Mozilla/5.0 (X11; Linux i686 on x86_64; rv:28.0) Gecko/20100101 Firefox/28.0'
	msg.getRequestHeader().setHeader('User-Agent', ua)
	return true
}

function proxyResponse(msg) {
	// Leave the response alone
	return true
}

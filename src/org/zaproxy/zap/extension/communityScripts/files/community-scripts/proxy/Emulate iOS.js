// This script was lazily crafted by Anthony Cozamanis, kurobeats@yahoo.co.jp

function proxyRequest(msg) {
	var ua
	ua = 'Mozilla/5.0 (iPhone; CPU iPhone OS 5_1 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9B176 Safari/7534.48.3'
	msg.getRequestHeader().setHeader('User-Agent', ua)
	return true
}

function proxyResponse(msg) {
	// Leave the response alone
	return true
}

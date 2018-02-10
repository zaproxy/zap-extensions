// This script was lazily crafted by Anthony Cozamanis, kurobeats@yahoo.co.jp

function proxyRequest(msg) {
	var ua
	ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.74.9 (KHTML, like Gecko) Version/7.0.2 Safari/537.74.9'
	msg.getRequestHeader().setHeader('User-Agent', ua)
	return true
}

function proxyResponse(msg) {
	// Leave the response alone
	return true
}

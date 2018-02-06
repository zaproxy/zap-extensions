// This script was lazily crafted by Anthony Cozamanis, kurobeats@yahoo.co.jp

function proxyRequest(msg) {
	var ua
	ua = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/33.0.1750.154 Safari/537.36'
	msg.getRequestHeader().setHeader('User-Agent', ua)
	return true
}

function proxyResponse(msg) {
	// Leave the response alone
	return true
}

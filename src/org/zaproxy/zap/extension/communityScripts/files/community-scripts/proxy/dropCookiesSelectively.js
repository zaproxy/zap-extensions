//@zaproxy-proxy

var globalCookies = ['CONSENT', 'GZ', 'SID']

function proxyRequest(msg) {
    var cookies = msg.getRequestHeader().getHttpCookies() // This is a List<HttpCookie>
    var iterator = cookies.iterator()
    while (iterator.hasNext()) {
        var cookie = iterator.next() // This is a HttpCookie
        if (globalCookies.indexOf(cookie.name) > -1) {
            iterator.remove()
            print('Stripped away: ' + cookie.name)
        }
    }
    msg.getRequestHeader().setCookies(cookies)
    return true
}

function proxyResponse(msg) {
    return true
}

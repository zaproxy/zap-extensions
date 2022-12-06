// This script handles out-of-band interactions.
// Change it to do whatever you want to do :)

var Control = Java.type("org.parosproxy.paros.control.Control")
var extOast = Control.getSingleton().getExtensionLoader().getExtension("ExtensionOast")
var boast = extOast.getBoastService()
var interactsh = extOast.getInteractshService()

function requestHandler(request) {
    print("Source: ", request.getSource())
    print("Referer: ", request.getReferer())
    print("Handler: ", request.getHandler())

    var msg = request.getHistoryReference().getHttpMessage()
    print("Request Header:\n", msg.getRequestHeader())
    print("Request Body:\n", msg.getRequestBody())
    print()
}

function install(helper) {
    boast.addOastRequestHandler(requestHandler)
    interactsh.addOastRequestHandler(requestHandler)
    print("OAST Request handler registered.")
}

function uninstall(helper) {
    boast.removeOastRequestHandler(requestHandler)
    interactsh.removeOastRequestHandler(requestHandler)
    print("OAST Request handler unregistered.")
}

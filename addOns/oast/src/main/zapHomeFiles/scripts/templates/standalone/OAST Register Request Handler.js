// This script registers an OAST message handler.
// Change it to do whatever you want to do :)

var Control = Java.type("org.parosproxy.paros.control.Control")
var extOast = Control.getSingleton().getExtensionLoader().getExtension("ExtensionOast")
var boast = extOast.getBoastService()

function requestHandler(request) {
    print("Source: ", request.getSource())
    print("Referer: ", request.getReferer())
    print("Handler: ", request.getHandler())
    print()
}

boast.addOastRequestHandler(requestHandler)
print("OAST Request handler registered.")

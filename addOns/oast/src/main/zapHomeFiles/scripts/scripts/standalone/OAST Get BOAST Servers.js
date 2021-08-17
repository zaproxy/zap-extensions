// This script lists the details of all registered BOAST Servers.

var Control = Java.type("org.parosproxy.paros.control.Control")
var extOast = Control.getSingleton().getExtensionLoader().getExtension("ExtensionOast")
var boast = extOast.getBoastService()
var registeredServers = boast.getRegisteredServers()

function printServerInfo(s) {
    print("Server URI: ", s.getUri())
    print("ID: ", s.getId())
    print("Payload: ", s.getPayload())
    print("Canary: ", s.getCanary())
    print()
}

if (registeredServers.isEmpty()) {
    print("No Servers Registered.")
    // print("Registering a server now...")
    // var server = boast.register("https://odiss.eu:1337/events")
    // printServerInfo(server) 
} else {
    registeredServers.forEach(printServerInfo)
}

// This script demonstrates how to get Interactsh payloads in scripts.

var extOast = control.getExtensionLoader().getExtension("ExtensionOast")
var interactsh = extOast.getInteractshService()

if (!interactsh.isRegistered()) {
    // Set the server URL you're using between the quotes below
    interactsh.getParam().setServerUrl("")
    // interactsh.getParam().setAuthToken("auth token value")
    interactsh.register()
}

print(interactsh.getNewPayload())

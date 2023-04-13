// This script demonstrates how to get Interactsh payloads in scripts.

var extOast = control.getExtensionLoader().getExtension("ExtensionOast")
var interactsh = extOast.getInteractshService()

if (!interactsh.isRegistered()) {
    interactsh.getParam().setServerUrl("https://interact.sh")
    // interactsh.getParam().setAuthToken("auth token value")
    interactsh.register()
}

print(interactsh.getNewPayload())

version = "7"
description = "Adds a set of tools for testing access control in web applications."

zapAddOn {
    addOnName.set("Access Control Testing")
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/access-control-testing/")
    }

    apiClientGen {
        api.set("org.zaproxy.zap.extension.accessControl.AccessControlAPI")
        messages.set(file("src/main/resources/org/zaproxy/zap/extension/accessControl/resources/Messages.properties"))
    }
}

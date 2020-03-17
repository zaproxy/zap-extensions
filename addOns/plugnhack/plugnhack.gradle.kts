import org.zaproxy.gradle.addon.AddOnStatus

version = "12"
description = "Supports the Mozilla Plug-n-Hack standard: https://developer.mozilla.org/en-US/docs/Plug-n-Hack."

zapAddOn {
    addOnName.set("Plug-n-Hack Configuration")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/plug-n-hack/")
    }

    apiClientGen {
        api.set("org.zaproxy.zap.extension.plugnhack.PlugNHackAPI")
        messages.set(file("src/main/resources/org/zaproxy/zap/extension/plugnhack/resources/Messages.properties"))
    }
}

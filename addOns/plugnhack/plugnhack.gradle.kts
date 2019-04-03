import org.zaproxy.gradle.addon.AddOnStatus

version = "12"
description = "Supports the Mozilla Plug-n-Hack standard: https://developer.mozilla.org/en-US/docs/Plug-n-Hack."

zapAddOn {
    addOnName.set("Plug-n-Hack Configuration")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.7.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://developer.mozilla.org/en-US/docs/Plug-n-Hack")
    }

    apiClientGen {
        api.set("org.zaproxy.zap.extension.plugnhack.PlugNHackAPI")
        messages.set(file("src/main/resources/org/zaproxy/zap/extension/plugnhack/resources/Messages.properties"))
    }
}

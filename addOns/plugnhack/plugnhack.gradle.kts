import org.zaproxy.gradle.addon.AddOnStatus

description = "Supports the Mozilla Plug-n-Hack standard: https://developer.mozilla.org/en-US/docs/Plug-n-Hack."

zapAddOn {
    addOnName.set("Plug-n-Hack Configuration")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.11.1")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/plug-n-hack/")

        dependencies {
            addOns {
                register("network") {
                    version.set(">= 0.2.0")
                }
            }
        }
    }

    apiClientGen {
        api.set("org.zaproxy.zap.extension.plugnhack.PlugNHackAPI")
        messages.set(file("src/main/resources/org/zaproxy/zap/extension/plugnhack/resources/Messages.properties"))
    }
}

dependencies {
    compileOnly(parent!!.childProjects.get("network")!!)
}

import org.zaproxy.gradle.addon.AddOnStatus

description = "Supports the Mozilla Plug-n-Hack standard: https://developer.mozilla.org/en-US/docs/Plug-n-Hack."

zapAddOn {
    addOnName.set("Plug-n-Hack Configuration")
    addOnStatus.set(AddOnStatus.BETA)

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

        extensions {
            register("org.zaproxy.zap.extension.plugnhack.manualsend.ExtensionPlugNHackManualSend") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.plugnhack.manualsend"))
                }
                dependencies {
                    addOns {
                        register("requester") {
                            version.set("7.*")
                        }
                    }
                }
            }
            register("org.zaproxy.addon.brk.ExtensionBreak") {
                classnames {
                    allowed.set(listOf("org.zaproxy.addon.brk.ExtensionBreak"))
                }
                dependencies {
                    addOns {
                        register("brk") {
                            version.set("0.1.0*")
                        }
                    }
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
    zapAddOn("network")
    zapAddOn("requester")
    zapAddOn("brk")
}

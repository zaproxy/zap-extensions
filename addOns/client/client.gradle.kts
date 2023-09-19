description = "Exposes client (browser) side information in ZAP using Firefox and Chrome extensions."

zapAddOn {
    addOnName.set("Client Side Integration")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/client-side-integration/")
        extensions {
            register("org.zaproxy.addon.client.zest.ExtensionClientZest") {
                classnames {
                    allowed.set(listOf("org.zaproxy.addon.client.zest"))
                }
                dependencies {
                    addOns {
                        register("zest") {
                            version.set(">=40")
                        }
                    }
                }
            }
        }
        dependencies {
            addOns {
                register("selenium") {
                    version.set("15.*")
                }
                register("network") {
                    version.set(">=0.8.0")
                }
            }
        }
    }
}

crowdin {
    configuration {
        val resourcesPath = "org/zaproxy/addon/${zapAddOn.addOnId.get()}/resources/"
        tokens.put("%messagesPath%", resourcesPath)
        tokens.put("%helpPath%", resourcesPath)
    }
}

dependencies {
    zapAddOn("selenium")
    zapAddOn("network")
    zapAddOn("zest")

    testImplementation(project(":testutils"))
}

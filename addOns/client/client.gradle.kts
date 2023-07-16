version = "0.0.1"
description = "Exposes client (browser) side information in ZAP using Firefox and Chrome extensions."

zapAddOn {
    addOnName.set("Client Side Integration")
    zapVersion.set("2.13.0")

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
                            version.set(">=39")
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

    implementation("org.zaproxy:zest:0.18.0") {
        // Provided by Selenium add-on.
        exclude(group = "org.seleniumhq.selenium")
        // Provided by ZAP.
        exclude(group = "net.htmlparser.jericho", module = "jericho-html")
    }
    testImplementation(project(":testutils"))
}

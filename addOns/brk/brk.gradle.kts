description = "Exposes client (browser) side information in ZAP using Firefox and Chrome extensions."

zapAddOn {
    addOnName.set("Break")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/brk/")
        extensions {
        
        }
        dependencies {
            addOns {
                register("selenium") {
                    version.set(">=15.14.0")
                }
                register("network") {
                    version.set(">=0.8.0")
                }
                register("commonlib")
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
    zapAddOn("commonlib")
    zapAddOn("selenium")
    zapAddOn("network")

    testImplementation(project(":testutils"))
}

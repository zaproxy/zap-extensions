version = "0.0.1"
description = "Exposes client (browser) side information in ZAP using Firefox and Chrome extensions."

zapAddOn {
    addOnName.set("Client Side Integration")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/client-side-integration/")
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
    compileOnly(parent!!.childProjects.get("selenium")!!)
    compileOnly(parent!!.childProjects.get("network")!!)

    testImplementation(project(":testutils"))
}

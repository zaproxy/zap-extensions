description = "Authentication Helper"

zapAddOn {
    addOnName.set("Authentication Helper")
    zapVersion.set("2.12.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/authentication-helper/")
        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.13.0 & < 2.0.0")
                }
                register("network") {
                    version.set(">=0.6.0")
                }
                register("selenium") {
                    version.set("15.*")
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
    testImplementation(parent!!.childProjects.get("network")!!)
    testImplementation(parent!!.childProjects.get("selenium")!!)
}

description = "An add-on to retest for presence/absence of previously generated alerts."

zapAddOn {
    addOnName.set("Retest")
    zapVersion.set("2.10.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/retest/")
        dependencies {
            addOns {
                register("automation") {
                    version.set(">=0.5.0")
                }
            }
        }
    }

    apiClientGen {
        api.set("org.zaproxy.addon.retest.RetestApi")
        messages.set(file("src/main/resources/org/zaproxy/addon/retest/resources/Messages.properties"))
    }
}

dependencies {
    compileOnly(parent!!.childProjects.get("automation")!!)
    testImplementation(parent!!.childProjects.get("automation")!!)
    testImplementation(project(":testutils"))
}

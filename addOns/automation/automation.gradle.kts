import org.zaproxy.gradle.addon.AddOnStatus

description = "Automation Framework."

zapAddOn {
    addOnName.set("Automation Framework")
    addOnStatus.set(AddOnStatus.BETA)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/automation-framework/")

        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.17.0 & < 2.0.0")
                }
                register("network") {
                    version.set(">= 0.15.0 & < 1.0.0")
                }
            }
        }
    }

    apiClientGen {
        api.set("org.zaproxy.addon.automation.AutomationAPI")
        messages.set(file("src/main/resources/org/zaproxy/addon/automation/resources/Messages.properties"))
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
    zapAddOn("network")

    testImplementation(project(":testutils"))
}

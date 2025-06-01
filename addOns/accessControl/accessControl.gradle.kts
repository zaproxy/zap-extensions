description = "Adds a set of tools for testing access control in web applications."

zapAddOn {
    addOnName.set("Access Control Testing")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/access-control-testing/")

        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.17.0 & < 2.0.0")
                }
            }
        }
    }

    apiClientGen {
        api.set("org.zaproxy.zap.extension.accessControl.AccessControlAPI")
        messages.set(file("src/main/resources/org/zaproxy/zap/extension/accessControl/resources/Messages.properties"))
    }
}

dependencies {
    zapAddOn("commonlib")

    testImplementation(project(":testutils"))
}

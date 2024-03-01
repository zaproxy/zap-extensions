description = "Identify hidden, unlinked parameters. Useful for finding web cache poisoning vulnerabilities."

zapAddOn {
    addOnName.set("Parameter Digger")

    manifest {
        author.set("ZAP Dev Team and Arkaprabha Chakraborty")
        url.set("https://www.zaproxy.org/docs/desktop/addons/parameter-digger/")

        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.23.0 & < 2.0.0")
                }
            }
        }
    }
}

dependencies {
    zapAddOn("commonlib")

    testImplementation(project(":testutils"))
}

crowdin {
    configuration {
        val resourcesPath = "org/zaproxy/addon/${zapAddOn.addOnId.get()}/resources/"
        tokens.put("%messagesPath%", resourcesPath)
        tokens.put("%helpPath%", resourcesPath)
    }
}

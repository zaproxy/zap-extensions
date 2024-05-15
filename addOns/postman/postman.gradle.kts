description = "Imports and spiders Postman collections."

zapAddOn {
    addOnName.set("Postman Support")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/postman-support/")

        extensions {
            register("org.zaproxy.addon.postman.automation.ExtensionPostmanAutomation") {
                classnames {
                    allowed.set(listOf("org.zaproxy.addon.postman.automation"))
                }
                dependencies {
                    addOns {
                        register("automation") {
                            version.set(">=0.31.0")
                        }
                    }
                }
            }
        }

        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.16.0 & < 2.0.0")
                }
            }
        }
    }

    apiClientGen {
        api.set("org.zaproxy.addon.postman.PostmanApi")
        messages.set(file("src/main/resources/org/zaproxy/addon/postman/resources/Messages.properties"))
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
    zapAddOn("automation")
    zapAddOn("commonlib")

    testImplementation(project(":testutils"))
}

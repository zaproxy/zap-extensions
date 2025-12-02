description = "An add-on providing additional insights into what ZAP finds."

zapAddOn {
    addOnName.set("Insights")

    manifest {
        author.set("ZAP Dev Team")
        extensions {
            register("org.zaproxy.addon.insights.report.ExtensionInsightsReport") {
                classnames {
                    allowed.set(listOf("org.zaproxy.addon.insights.report"))
                }
                dependencies {
                    addOns {
                        register("reports") {
                            version.set(">=0.39.0")
                        }
                    }
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
    zapAddOn("reports")
    testImplementation(project(":testutils"))
}

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
            register("org.zaproxy.addon.insights.automation.ExtensionInsightsAutomation") {
                classnames {
                    allowed.set(listOf("org.zaproxy.addon.insights.automation"))
                }
                dependencies {
                    addOns {
                        register("automation") {
                            version.set(">=0.58.0")
                        }
                        register("commonlib")
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
    zapAddOn("automation")
    zapAddOn("commonlib")
    zapAddOn("reports")
    testImplementation(project(":testutils"))
}

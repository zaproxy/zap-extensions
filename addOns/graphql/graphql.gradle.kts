description = "Inspect and attack GraphQL endpoints."

zapAddOn {
    addOnName.set("GraphQL Support")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/graphql-support/")
        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.17.0 & < 2.0.0")
                }
            }
        }
        extensions {
            register("org.zaproxy.addon.graphql.automation.ExtensionGraphQlAutomation") {
                classnames {
                    allowed.set(listOf("org.zaproxy.addon.graphql.automation"))
                }
                dependencies {
                    addOns {
                        register("automation") {
                            version.set(">=0.31.0")
                        }
                    }
                }
            }

            register("org.zaproxy.addon.graphql.spider.ExtensionGraphQlSpider") {
                classnames {
                    allowed.set(listOf("org.zaproxy.addon.graphql.spider"))
                }
                dependencies {
                    addOns {
                        register("spider") {
                            version.set(">=0.1.0")
                        }
                    }
                }
            }
        }
    }

    apiClientGen {
        api.set("org.zaproxy.addon.graphql.GraphQlApi")
        options.set("org.zaproxy.addon.graphql.GraphQlParam")
        messages.set(file("src/main/resources/org/zaproxy/addon/graphql/resources/Messages.properties"))
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
    zapAddOn("spider")

    implementation("com.graphql-java:graphql-java:22.0")

    testImplementation(project(":testutils"))
    testImplementation(libs.log4j.core)
}

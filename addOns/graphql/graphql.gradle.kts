description = "Inspect and attack GraphQL endpoints."

zapAddOn {
    addOnName.set("GraphQL Support")
    zapVersion.set("2.11.1")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/graphql-support/")
        extensions {
            register("org.zaproxy.addon.graphql.automation.ExtensionGraphQlAutomation") {
                classnames {
                    allowed.set(listOf("org.zaproxy.addon.graphql.automation"))
                }
                dependencies {
                    addOns {
                        register("automation") {
                            version.set(">=0.12.0")
                        }
                    }
                }
            }

            register("org.zaproxy.addon.graphql.formhandler.ExtensionGraphQlFormHandler") {
                classnames {
                    allowed.set(listOf("org.zaproxy.addon.graphql.formhandler"))
                }
                dependencies {
                    addOns {
                        register("formhandler") {
                            version.set(">=6.0.0 & < 7.0.0")
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
    compileOnly(parent!!.childProjects.get("automation")!!)
    compileOnly(parent!!.childProjects.get("formhandler")!!)
    compileOnly(parent!!.childProjects.get("spider")!!)
    implementation("com.google.code.gson:gson:2.8.8")
    implementation("com.graphql-java:graphql-java:18.2")

    testImplementation(parent!!.childProjects.get("automation")!!)
    testImplementation(parent!!.childProjects.get("formhandler")!!)
    testImplementation(parent!!.childProjects.get("spider")!!)
    testImplementation(project(":testutils"))
}

import org.zaproxy.gradle.addon.AddOnStatus

description = "Spider used for automatically finding URIs on a site."

zapAddOn {
    addOnName.set("Spider")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.12.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/spider/")

        dependencies {
            addOns {
                register("database")
                register("network") {
                    version.set(">=0.3.0")
                }
            }
        }

        extensions {
            register("org.zaproxy.addon.spider.automation.ExtensionSpiderAutomation") {
                classnames {
                    allowed.set(listOf("org.zaproxy.addon.spider.automation"))
                }
                dependencies {
                    addOns {
                        register("automation") {
                            version.set(">=0.17.0")
                        }
                    }
                }
            }

            register("org.zaproxy.addon.spider.formhandler.ExtensionSpiderFormHandler") {
                classnames {
                    allowed.set(listOf("org.zaproxy.addon.spider.formhandler"))
                }
                dependencies {
                    addOns {
                        register("formhandler") {
                            version.set(">=6.0.0 & < 7.0.0")
                        }
                    }
                }
            }
        }
    }

    apiClientGen {
        api.set("org.zaproxy.addon.spider.SpiderAPI")
        options.set("org.zaproxy.addon.spider.SpiderParam")
    }
}

crowdin {
    configuration {
        val path = "org/zaproxy/addon/spider/resources/"
        tokens.put("%messagesPath%", path)
        tokens.put("%helpPath%", path)
    }
}

dependencies {
    compileOnly(parent!!.childProjects.get("automation")!!)
    compileOnly(parent!!.childProjects.get("database")!!)
    compileOnly(parent!!.childProjects.get("formhandler")!!)
    compileOnly(parent!!.childProjects.get("network")!!)

    testImplementation(parent!!.childProjects.get("automation")!!)
    testImplementation(parent!!.childProjects.get("database")!!)
    testImplementation(parent!!.childProjects.get("formhandler")!!)
    testImplementation(parent!!.childProjects.get("network")!!)
    testImplementation(project(":testutils"))
}

spotless {
    javaWith3rdPartyFormatted(
        project,
        listOf(
            "src/**/UrlCanonicalizer.java",
            "src/**/UrlResolver.java"
        )
    )
}

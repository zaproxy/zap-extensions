import org.zaproxy.gradle.addon.AddOnStatus

description = "Spider used for automatically finding URIs on a site."

zapAddOn {
    addOnName.set("Spider")
    addOnStatus.set(AddOnStatus.RELEASE)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/spider/")

        dependencies {
            addOns {
                register("database")
                register("network") {
                    version.set(">=0.3.0")
                }
                register("commonlib") {
                    version.set(">= 1.13.0 & < 2.0.0")
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
    zapAddOn("automation")
    zapAddOn("commonlib")
    zapAddOn("database")
    zapAddOn("formhandler")
    zapAddOn("network")

    implementation("io.kaitai:kaitai-struct-runtime:0.10")

    testImplementation(project(":testutils"))
}

spotless {
    javaWith3rdPartyFormatted(
        project,
        listOf(
            "src/**/UrlCanonicalizer.java",
            "src/**/UrlResolver.java",
        ),
        listOf("src/**/DsStore.java"),
    )
}

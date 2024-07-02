import org.zaproxy.gradle.addon.AddOnStatus

description = "Helps identify and set up authentication handling"

zapAddOn {
    addOnName.set("Authentication Helper")
    addOnStatus.set(AddOnStatus.BETA)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/authentication-helper/")
        extensions {
            register("org.zaproxy.addon.authhelper.spiderajax.ExtensionAuthhelperAjax") {
                classnames {
                    allowed.set(listOf("org.zaproxy.addon.authhelper.spiderajax"))
                }
                dependencies {
                    addOns {
                        register("spiderAjax") {
                            version.set(">=23.22.0")
                        }
                    }
                }
            }
            register("org.zaproxy.addon.authhelper.client.ExtensionAuthhelperClient") {
                classnames {
                    allowed.set(listOf("org.zaproxy.addon.authhelper.client"))
                }
                dependencies {
                    addOns {
                        register("client") {
                            version.set(">=0.11.0")
                        }
                    }
                }
            }
        }
        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.13.0 & < 2.0.0")
                }
                register("network") {
                    version.set(">=0.6.0")
                }
                register("pscan") {
                    version.set(">= 0.1.0 & < 1.0.0")
                }
                register("selenium") {
                    version.set("15.*")
                }
                register("zest") {
                    version.set(">=48.1.0")
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
    zapAddOn("commonlib")
    zapAddOn("network")
    zapAddOn("pscan")
    zapAddOn("selenium")
    zapAddOn("spiderAjax")
    zapAddOn("client")
    zapAddOn("zest")

    testImplementation(project(":testutils"))
}

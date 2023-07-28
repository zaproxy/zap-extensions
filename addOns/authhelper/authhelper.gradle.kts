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
                            version.set(">=23.15.0")
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
                register("selenium") {
                    version.set("15.*")
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
    zapAddOn("selenium")
    zapAddOn("spiderAjax")

    testImplementation(project(":testutils"))
}

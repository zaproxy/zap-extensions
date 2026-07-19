import org.zaproxy.gradle.addon.AddOnStatus

plugins {
    id("org.zaproxy.gradle.jdo-enhance")
}

description = "Tracks parameters, cookies, and header values on a site by site basis."

zapAddOn {
    addOnName.set("Params")
    addOnStatus.set(AddOnStatus.RELEASE)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/params/")

        dependencies {
            addOns {
                register("database") {
                    version.set(">=0.8.0 & < 1.0.0")
                }
                register("pscan") {
                    version.set(">= 0.1.0 & < 1.0.0")
                }
            }
        }

        extensions {
            register("org.zaproxy.addon.params.automation.ExtensionParamsAutomation") {
                classnames {
                    allowed.set(listOf("org.zaproxy.addon.params.automation"))
                }
                dependencies {
                    addOns {
                        register("automation") {
                            version.set(">= 0.61.0 & < 1.0.0")
                        }
                    }
                }
            }
        }
    }

    apiClientGen {
        api.set("org.zaproxy.addon.params.ParamsAPI")
    }
}

crowdin {
    configuration {
        val path = "org/zaproxy/addon/params/resources/"
        tokens.put("%messagesPath%", path)
        tokens.put("%helpPath%", path)
    }
}

jdoEnhance {
    persistenceUnitName.set(zapAddOn.addOnId.get())
}

dependencies {
    jdoEnhance(libs.database.datanucleusJdo)

    zapAddOn("automation")
    zapAddOn("database")
    zapAddOn("pscan")

    testImplementation(project(":testutils"))
}

import org.zaproxy.gradle.addon.AddOnStatus

plugins {
    id("org.zaproxy.gradle.jdo-enhance")
}

description = "Allows you to exploit out-of-band vulnerabilities"

zapAddOn {
    addOnName.set("OAST Support")
    addOnStatus.set(AddOnStatus.BETA)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/oast-support/")

        dependencies {
            addOns {
                register("database") {
                    version.set(">= 0.6.0")
                }
                register("network") {
                    version.set(">= 0.1.0")
                }
            }
        }

        extensions {
            register("org.zaproxy.addon.oast.scripts.ExtensionOastScripts") {
                classnames {
                    allowed.set(listOf("org.zaproxy.addon.oast.scripts"))
                }
                dependencies {
                    addOns {
                        register("scripts")
                        register("graaljs")
                    }
                }
            }
        }
    }
    apiClientGen {
        api.set("org.zaproxy.addon.oast.OastApi")
        messages.set(file("src/main/resources/org/zaproxy/addon/oast/resources/Messages.properties"))
    }
}

jdoEnhance {
    persistenceUnitName.set(zapAddOn.addOnId.get())
}

crowdin {
    configuration {
        val resourcesPath = "org/zaproxy/addon/${zapAddOn.addOnId.get()}/resources/"
        tokens.put("%messagesPath%", resourcesPath)
        tokens.put("%helpPath%", resourcesPath)
    }
}

dependencies {
    jdoEnhance(libs.database.datanucleusJdo)

    zapAddOn("database")
    zapAddOn("graaljs")
    zapAddOn("network")

    testImplementation(project(":testutils"))
}

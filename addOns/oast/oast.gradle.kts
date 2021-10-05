description = "Allows you to exploit out-of-band vulnerabilities"

zapAddOn {
    addOnName.set("OAST Support")
    zapVersion.set("2.11.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/oast-support/")

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

crowdin {
    configuration {
        val resourcesPath = "org/zaproxy/addon/${zapAddOn.addOnId.get()}/resources/"
        tokens.put("%messagesPath%", resourcesPath)
        tokens.put("%helpPath%", resourcesPath)
    }
}

dependencies {
    compileOnly(parent!!.childProjects["graaljs"]!!)

    testImplementation(project(":testutils"))
}

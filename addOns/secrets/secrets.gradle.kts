description = "Detects secrets (such as API keys and tokens) disclosed in HTTP responses."

zapAddOn {
    addOnName.set("Secrets")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/secrets/")
        bundle {
            baseName.set("org.zaproxy.addon.secrets.resources.Messages")
            prefix.set("secrets")
        }
        helpSet {
            baseName.set("org.zaproxy.addon.secrets.resources.help%LC%.helpset")
            localeToken.set("%LC%")
        }
        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.45.0 & < 2.0.0")
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

    implementation(libs.secrets.re2j)
    testImplementation(project(":testutils"))
}

import org.zaproxy.gradle.addon.AddOnStatus

description = "Retire.js"

zapAddOn {
    addOnName.set("Retire.js")
    addOnStatus.set(AddOnStatus.RELEASE)

    manifest {
        author.set("Nikita Mundhada and the ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/retire.js/")
        bundle {
            baseName.set("org.zaproxy.addon.retire.resources.Messages")
            prefix.set("retire")
        }
        helpSet {
            baseName.set("org.zaproxy.addon.retire.resources.help%LC%.helpset")
            localeToken.set("%LC%")
        }
        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.16.0 & < 2.0.0")
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

    testImplementation(project(":testutils"))
}

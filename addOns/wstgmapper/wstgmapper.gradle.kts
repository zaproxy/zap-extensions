import org.zaproxy.gradle.addon.AddOnStatus

description =
    "WSTG Mapper provides a WSTG compliance dashboard that maps ZAP alerts to " +
    "OWASP Web Security Testing Guide coverage."

zapAddOn {
    addOnName.set("WSTG Mapper")
    addOnStatus.set(AddOnStatus.ALPHA)

    manifest {
        author.set("Theodoros Vartamtzidis")
        url.set("https://www.zaproxy.org/docs/desktop/addons/wstg-mapper/")
        bundle {
            baseName.set("org.zaproxy.addon.wstgmapper.resources.Messages")
            prefix.set("wstgmapper")
        }
        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.38.0 & < 2.0.0")
                }
            }
        }
    }
}

crowdin {
    configuration {
        val resourcesPath = "org/zaproxy/addon/${zapAddOn.addOnId.get()}/resources/"
        tokens.put("%messagesPath%", resourcesPath)
    }
}

dependencies {
    zapAddOn("commonlib")
    testImplementation(project(":testutils"))
}

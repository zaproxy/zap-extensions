import org.zaproxy.gradle.addon.AddOnStatus

description = "Adds encode/decode/hash dialog and support for scripted processors as well"

zapAddOn {
    addOnName.set("Encoder")
    addOnStatus.set(AddOnStatus.RELEASE)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/encode-decode-hash/")
        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">=1.23.0")
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

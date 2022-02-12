import org.zaproxy.gradle.addon.AddOnStatus

description = "Retire.js"

zapAddOn {
    addOnName.set("Retire.js")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.11.1")

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
                    version.set(">= 1.7.0 & < 2.0.0")
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
    compileOnly(parent!!.childProjects.get("commonlib")!!)

    implementation("com.google.code.gson:gson:2.8.8")

    testImplementation(parent!!.childProjects.get("commonlib")!!)
    testImplementation(project(":testutils"))
}

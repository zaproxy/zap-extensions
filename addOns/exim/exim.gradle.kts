import org.zaproxy.gradle.addon.AddOnStatus

description = "Import and Export functionality"

zapAddOn {
    addOnName.set("Import/Export")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.11.1")

    manifest {
        author.set("ZAP Dev Team & thatsn0tmysite")
        url.set("https://www.zaproxy.org/docs/desktop/addons/import-export/")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }
        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.8.0 & < 2.0.0")
                }
            }
        }
    }
}

crowdin {
    configuration {
        tokens.put("%messagesPath%", "org/zaproxy/addon/${zapAddOn.addOnId.get()}/resources/")
        tokens.put("%helpPath%", "")
    }
}

dependencies {
    compileOnly(parent!!.childProjects.get("commonlib")!!)
    implementation(files("lib/org.jwall.web.audit-0.2.15.jar"))

    testImplementation(parent!!.childProjects.get("commonlib")!!)
    testImplementation(parent!!.childProjects.get("commonlib")!!.sourceSets.test.get().output)
    testImplementation(project(":testutils"))
}

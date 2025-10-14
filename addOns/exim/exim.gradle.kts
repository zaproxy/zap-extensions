import org.zaproxy.gradle.addon.AddOnStatus

description = "Import and Export functionality"

zapAddOn {
    addOnName.set("Import/Export")
    addOnStatus.set(AddOnStatus.BETA)

    manifest {
        author.set("ZAP Dev Team & thatsn0tmysite")
        url.set("https://www.zaproxy.org/docs/desktop/addons/import-export/")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }
        extensions {
            register("org.zaproxy.addon.exim.automation.ExtensionEximAutomation") {
                classnames {
                    allowed.set(listOf("org.zaproxy.addon.exim.automation"))
                }
                dependencies {
                    addOns {
                        register("automation") {
                            version.set(">=0.31.0")
                        }
                    }
                }
            }
        }
        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.38.0 & < 2.0.0")
                }
            }
        }
    }

    apiClientGen {
        api.set("org.zaproxy.addon.exim.ImportExportApi")
        messages.set(file("src/main/resources/org/zaproxy/addon/exim/resources/Messages.properties"))
    }
}

crowdin {
    configuration {
        tokens.put("%messagesPath%", "org/zaproxy/addon/${zapAddOn.addOnId.get()}/resources/")
        tokens.put("%helpPath%", "")
    }
}

dependencies {
    zapAddOn("automation")
    zapAddOn("commonlib")

    implementation(files("lib/org.jwall.web.audit-0.2.15.jar"))
    implementation(libs.exim.harReader) {
        // Provided by commonlib add-on:
        exclude(group = "com.fasterxml.jackson.core")
        exclude(group = "com.fasterxml.jackson.datatype")
    }
    implementation(files("lib/pkts-core-3.0.11-tcp-streams-branch.jar"))
    implementation(files("lib/pkts-streams-3.0.11-tcp-streams-branch.jar"))
    implementation(files("lib/pkts-buffers-3.0.11-tcp-streams-branch.jar"))
    implementation(libs.exim.hektorFsm)
    implementation(libs.log4j.slf4j)

    testImplementation(parent!!.childProjects.get("commonlib")!!.sourceSets.test.get().output)
    testImplementation(project(":testutils"))
    testImplementation(libs.log4j.core)
}

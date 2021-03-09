version = "0.0.1"
description = "Official ZAP Reports."

zapAddOn {
    addOnName.set("Report Generation")
    zapVersion.set("2.10.0")

    manifest {
        author.set("ZAP Dev Team")
        extensions {
            register("org.zaproxy.addon.reports.automation.ExtensionReportAutomation") {
                classnames {
                    allowed.set(listOf("org.zaproxy.addon.reports.automation"))
                }
                dependencies {
                    addOns {
                        register("automation") {
                            version.set("0.*")
                        }
                    }
                }
            }
        }
    }
}

dependencies {
    compileOnly(parent!!.childProjects.get("automation")!!)
    implementation("org.thymeleaf:thymeleaf:3.0.12.RELEASE")
    implementation("org.xhtmlrenderer:flying-saucer-pdf:9.1.20")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-yaml:2.12.0")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.12.0")
    implementation("org.snakeyaml:snakeyaml-engine:2.2.1")
    testImplementation(parent!!.childProjects.get("automation")!!)
    testImplementation(project(":testutils"))
}

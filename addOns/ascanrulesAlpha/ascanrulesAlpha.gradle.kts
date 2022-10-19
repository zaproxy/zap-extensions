description = "The alpha status Active Scanner rules"

zapAddOn {
    addOnName.set("Active scanner rules (alpha)")
    zapVersion.set("2.11.1")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/active-scan-rules-alpha/")

        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.9.0 & < 2.0.0")
                }
                register("oast") {
                    version.set(">= 0.7.0")
                }
            }
        }
    }
}

dependencies {
    compileOnly(parent!!.childProjects.get("commonlib")!!)
    compileOnly(parent!!.childProjects.get("oast")!!)

    testImplementation(parent!!.childProjects.get("commonlib")!!)
    testImplementation(parent!!.childProjects.get("network")!!)
    testImplementation(parent!!.childProjects.get("oast")!!)
    testImplementation(project(":testutils"))
}

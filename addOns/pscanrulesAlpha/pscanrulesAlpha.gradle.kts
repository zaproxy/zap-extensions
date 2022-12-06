description = "The alpha status Passive Scanner rules"

zapAddOn {
    addOnName.set("Passive scanner rules (alpha)")
    zapVersion.set("2.12.0")

    manifest {
        author.set("ZAP Dev Team")
        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.10.0 & < 2.0.0")
                }
            }
        }
        url.set("https://www.zaproxy.org/docs/desktop/addons/passive-scan-rules-alpha/")
    }
}

dependencies {
    compileOnly(parent!!.childProjects.get("commonlib")!!)

    testImplementation(parent!!.childProjects.get("commonlib")!!)
    testImplementation(project(":testutils"))
}

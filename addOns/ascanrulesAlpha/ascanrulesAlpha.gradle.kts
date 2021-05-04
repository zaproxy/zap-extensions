version = "31"
description = "The alpha quality Active Scanner rules"

zapAddOn {
    addOnName.set("Active scanner rules (alpha)")
    zapVersion.set("2.10.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/active-scan-rules-alpha/")

        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.3.0 & < 2.0.0")
                }
            }
        }
    }
}

dependencies {
    compileOnly(parent!!.childProjects.get("commonlib")!!)

    testImplementation(parent!!.childProjects.get("commonlib")!!)
    testImplementation(project(":testutils"))
}

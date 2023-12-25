description = "The alpha status Passive Scanner rules"

zapAddOn {
    addOnName.set("Passive scanner rules (alpha)")

    manifest {
        author.set("ZAP Dev Team")
        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.17.0 & < 2.0.0")
                }
            }
        }
        url.set("https://www.zaproxy.org/docs/desktop/addons/passive-scan-rules-alpha/")
    }
}

dependencies {
    zapAddOn("commonlib")

    implementation("com.google.re2j:re2j:1.7")
    testImplementation(project(":testutils"))
}

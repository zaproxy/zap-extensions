description = "The alpha status Passive Scanner rules"

zapAddOn {
    addOnName.set("Passive scanner rules (alpha)")

    manifest {
        author.set("ZAP Dev Team")
        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.38.0 & < 2.0.0")
                }
            }
        }
        url.set("https://www.zaproxy.org/docs/desktop/addons/passive-scan-rules-alpha/")
    }
}

dependencies {
    zapAddOn("commonlib")

    implementation(libs.pscanrulesAlpha.re2j)
    testImplementation(project(":testutils"))
}

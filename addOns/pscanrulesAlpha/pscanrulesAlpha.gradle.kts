description = "The alpha status Passive Scanner rules"

zapAddOn {
    addOnName.set("Passive scanner rules (alpha)")

    manifest {
        author.set("ZAP Dev Team")
        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.42.0 & < 2.0.0")
                }
            }
        }
        url.set("https://www.zaproxy.org/docs/desktop/addons/passive-scan-rules-alpha/")
    }
}

dependencies {
    zapAddOn("commonlib")

    implementation(platform(libs.commonlib.jackson.bom))
    implementation(libs.pscanrulesAlpha.jackson.dataformat.toml) {
        // Provided by commonlib add-on:
        exclude(group = "com.fasterxml.jackson.core")
    }
    implementation(libs.pscanrulesAlpha.re2j)
    testImplementation(project(":testutils"))
}

import org.zaproxy.gradle.addon.AddOnStatus

description = "The beta status Passive Scanner rules"

zapAddOn {
    addOnName.set("Passive scanner rules (beta)")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.11.1")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/passive-scan-rules-beta/")

        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.10.0 & < 2.0.0")
                }
            }
        }
    }
}

dependencies {
    implementation("com.google.re2j:re2j:1.6")

    compileOnly(parent!!.childProjects.get("commonlib")!!)

    testImplementation(parent!!.childProjects.get("commonlib")!!)
    testImplementation(project(":testutils"))
}

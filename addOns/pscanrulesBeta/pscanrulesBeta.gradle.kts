import org.zaproxy.gradle.addon.AddOnStatus

version = "24"
description = "The beta quality Passive Scanner rules"

zapAddOn {
    addOnName.set("Passive scanner rules (beta)")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/passive-scan-rules-beta/")

        dependencies {
            addOns {
                register("commonlib")
            }
        }
    }
}

dependencies {
    implementation("com.google.re2j:re2j:1.5")

    compileOnly(parent!!.childProjects.get("commonlib")!!)

    testImplementation(parent!!.childProjects.get("commonlib")!!)
    testImplementation(project(":testutils"))
}

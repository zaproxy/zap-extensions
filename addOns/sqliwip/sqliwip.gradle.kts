import org.zaproxy.gradle.addon.AddOnStatus

description = "Temporary add-on holding the work in progress modular SQL injection scan rule."

zapAddOn {
    addOnName.set("SQL Injection (WIP)")
    addOnStatus.set(AddOnStatus.ALPHA)

    manifest {
        author.set("ZAP Dev Team")

        bundle {
            baseName.set("org.zaproxy.addon.sqliwip.resources.Messages")
            prefix.set("sqliwip")
        }

        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.40.0 & < 2.0.0")
                }
            }
        }
    }
}

dependencies {
    zapAddOn("commonlib")

    testImplementation(project(":testutils"))
}

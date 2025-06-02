import org.zaproxy.gradle.addon.AddOnStatus

description = "Allows to port scan a target server"

zapAddOn {
    addOnName.set("Port Scanner")
    addOnStatus.set(AddOnStatus.BETA)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/port-scan/")

        dependencies {
            addOns {
                register("network") {
                    version.set(">=0.3.0")
                }
                register("commonlib") {
                    version.set(">= 1.23.0 & < 2.0.0")
                }
            }
        }
    }
}

dependencies {
    zapAddOn("commonlib")
    zapAddOn("network")

    testImplementation(project(":testutils"))
}

import org.zaproxy.gradle.addon.AddOnStatus

description = "Allows to port scan a target server"

zapAddOn {
    addOnName.set("Port Scanner")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.12.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/port-scan/")

        dependencies {
            addOns {
                register("network") {
                    version.set(">=0.3.0")
                }
            }
        }
    }
}

dependencies {
    compileOnly(parent!!.childProjects.get("network")!!)

    testImplementation(parent!!.childProjects.get("network")!!)
}

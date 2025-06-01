import org.zaproxy.gradle.addon.AddOnStatus

description = "Adds Groovy support to ZAP"

zapAddOn {
    addOnName.set("Groovy Support")
    addOnStatus.set(AddOnStatus.BETA)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/groovy-support/")
        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">=1.24.0")
                }
                register("scripts") {
                    version.set(">=45.2.0")
                }
            }
        }
    }
}

dependencies {
    zapAddOn("commonlib")
    zapAddOn("scripts")

    implementation("org.codehaus.groovy:groovy-all:3.0.14")

    testImplementation(project(":testutils"))
    testImplementation(project(":addOns:websocket"))
}

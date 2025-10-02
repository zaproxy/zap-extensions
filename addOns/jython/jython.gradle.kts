import org.zaproxy.gradle.addon.AddOnStatus

description = "Allows Python to be used for ZAP scripting - templates included"

zapAddOn {
    addOnName.set("Python Scripting")
    addOnStatus.set(AddOnStatus.BETA)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/python-scripting/")
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

    implementation(libs.jython.jython)

    testImplementation(project(":testutils"))
}

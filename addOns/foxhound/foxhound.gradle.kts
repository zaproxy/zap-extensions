import org.zaproxy.gradle.addon.AddOnStatus

description = "Capture and analysis of client-side data flows from the Foxhound browser."

zapAddOn {
    addOnName.set("Foxhound ZAP Add-on")
    addOnStatus.set(AddOnStatus.ALPHA)

    manifest {
        author.set("Thomas Barber")
        url.set("https://github.com/SAP/project-foxhound")
        // Don't search the add-on classes to prevent the inclusion
        // of the scanner, it's added/removed by the extension.
        classpath.setFrom(files())
        extensions {
            register("org.zaproxy.zap.extension.foxhound.ExtensionFoxhound")
        }
        dependencies {
            addOns {
                register("selenium") {
                    version.set(">=15.14.0")
                }
                register("network") {
                    version.set(">=0.1.0")
                }
                register("commonlib") {
                    version.set(">= 1.29.0 & < 2.0.0")
                }
                register("pscan") {
                    version.set(">= 0.1.0 & < 1.0.0")
                }
            }
        }
        pscanrules {
            register("org.zaproxy.zap.extension.foxhound.FoxhoundExportServer")
        }
    }
}

dependencies {
    zapAddOn("commonlib")
    zapAddOn("network")
    zapAddOn("selenium")
    zapAddOn("pscan")
    testImplementation("io.github.bonigarcia:webdrivermanager:5.7.0")
    testImplementation(project(":testutils"))
}

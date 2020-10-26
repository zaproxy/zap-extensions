import org.zaproxy.gradle.addon.AddOnStatus

version = "10"
description = "DOM XSS Active scanner rule"

zapAddOn {
    addOnName.set("DOM XSS Active scanner rule")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.9.0")

    manifest {
        author.set("Aabha Biyani, ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/dom-xss-active-scan-rule/")
        // Don't search the add-on classes to prevent the inclusion
        // of the scanner, it's added/removed by the extension.
        classpath.setFrom(files())
        extensions {
            register("org.zaproxy.zap.extension.domxss.ExtensionDomXSS")
        }
        dependencies {
            addOns {
                register("selenium") {
                    version.set("15.*")
                }
            }
        }
    }
}

dependencies {
    compileOnly(parent!!.childProjects.get("selenium")!!)
    testImplementation(parent!!.childProjects.get("selenium")!!)
    testImplementation("io.github.bonigarcia:webdrivermanager:4.2.2")
    testImplementation(project(":testutils"))
}

tasks.withType<Test>().configureEach {
    systemProperties.putAll(mapOf(
            "wdm.chromeDriverVersion" to "83.0.4103.39",
            "wdm.geckoDriverVersion" to "0.26.0",
            "wdm.forceCache" to "true"))
}

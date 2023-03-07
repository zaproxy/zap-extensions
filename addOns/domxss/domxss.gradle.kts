import org.zaproxy.gradle.addon.AddOnStatus

description = "DOM XSS Active scanner rule"

zapAddOn {
    addOnName.set("DOM XSS Active scanner rule")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.12.0")

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
                register("network") {
                    version.set(">=0.1.0")
                }
                register("selenium") {
                    version.set("15.*")
                }
                register("commonlib") {
                    version.set(">= 1.6.0 & < 2.0.0")
                }
            }
        }
    }
}

dependencies {
    compileOnly(parent!!.childProjects.get("commonlib")!!)
    compileOnly(parent!!.childProjects.get("network")!!)
    compileOnly(parent!!.childProjects.get("selenium")!!)
    testImplementation(parent!!.childProjects.get("commonlib")!!)
    testImplementation(parent!!.childProjects.get("network")!!)
    testImplementation(parent!!.childProjects.get("selenium")!!)
    testImplementation("io.github.bonigarcia:webdrivermanager:5.0.3")
    testImplementation(project(":testutils"))
}

tasks.withType<Test>().configureEach {
    systemProperties.putAll(
        mapOf(
            "wdm.chromeDriverVersion" to "108.0.5359.71",
            "wdm.geckoDriverVersion" to "0.32.0",
            "wdm.forceCache" to "true",
        ),
    )
}

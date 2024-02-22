import org.zaproxy.gradle.addon.AddOnStatus

description = "DOM XSS Active scanner rule"

zapAddOn {
    addOnName.set("DOM XSS Active scanner rule")
    addOnStatus.set(AddOnStatus.RELEASE)

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
                    version.set(">= 15.13.0")
                }
                register("commonlib") {
                    version.set(">= 1.17.0 & < 2.0.0")
                }
            }
        }
    }
}

dependencies {
    zapAddOn("commonlib")
    zapAddOn("network")
    zapAddOn("selenium")

    testImplementation("io.github.bonigarcia:webdrivermanager:5.7.0")
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

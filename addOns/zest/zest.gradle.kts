import org.zaproxy.gradle.addon.AddOnStatus

plugins {
    eclipse
}

eclipse {
    project {
        // Prevent collision with Zest library.
        name = "zestAddOn"
    }
}

description = "A graphical security scripting language, ZAPs macro language on steroids"

zapAddOn {
    addOnName.set("Zest - Graphical Security Scripting Language")
    addOnStatus.set(AddOnStatus.BETA)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/zest/")
        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">=1.24.0")
                }
                register("network") {
                    version.set(">=0.2.0")
                }
                register("scripts") {
                    version.set(">=45.2.0")
                }
                register("selenium") {
                    version.set(">= 15.13.0")
                }
            }
        }
    }
}

dependencies {
    zapAddOn("commonlib")
    zapAddOn("network")
    zapAddOn("scripts")
    zapAddOn("selenium")

    implementation("org.zaproxy:zest:0.21.0") {
        // Provided by commonlib add-on.
        exclude(group = "com.fasterxml.jackson")
        // Provided by Selenium add-on.
        exclude(group = "org.seleniumhq.selenium")
        // Provided by ZAP.
        exclude(group = "net.htmlparser.jericho", module = "jericho-html")
    }
    implementation("org.owasp.jbrofuzz:jbrofuzz-core:2.5.1") {
        // Only "jbrofuzz-core" is needed.
        setTransitive(false)
    }

    testImplementation(project(":testutils"))
}

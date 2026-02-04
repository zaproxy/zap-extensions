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
                    version.set(">=1.31.0")
                }
                register("network") {
                    version.set(">=0.2.0")
                }
                register("pscan") {
                    version.set(">= 0.1.0 & < 1.0.0")
                }
                register("scripts") {
                    version.set(">=45.2.0")
                }
                register("selenium") {
                    version.set(">= 15.44.0")
                }
            }
        }
    }
}

dependencies {
    zapAddOn("commonlib")
    zapAddOn("network")
    zapAddOn("pscan")
    zapAddOn("scripts")
    zapAddOn("selenium")

    api(libs.zest.zest) {
        // Provided by commonlib add-on.
        exclude(group = "com.fasterxml.jackson.core")
        exclude(group = "com.fasterxml.jackson.dataformat")
        // Provided by Selenium add-on.
        exclude(group = "org.seleniumhq.selenium")
        // Provided by ZAP.
        exclude(group = "net.htmlparser.jericho", module = "jericho-html")
    }
    implementation(libs.zest.jbrofuzzCore) {
        // Only "jbrofuzz-core" is needed.
        setTransitive(false)
    }

    testImplementation(project(":testutils"))
}

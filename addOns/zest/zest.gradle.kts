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

version = "34"
description = "A graphical security scripting language, ZAPs macro language on steroids"

zapAddOn {
    addOnName.set("Zest - Graphical Security Scripting Language")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/zest/")
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
    implementation("org.zaproxy:zest:0.15.0") {
        // Provided by Selenium add-on.
        exclude(group = "org.seleniumhq.selenium")
        exclude(group = "com.codeborne", module = "phantomjsdriver")
        // Provided by ZAP.
        exclude(group = "net.htmlparser.jericho", module = "jericho-html")
    }
    implementation("org.owasp.jbrofuzz:jbrofuzz-core:2.5.1") {
        // Only "jbrofuzz-core" is needed.
        setTransitive(false)
    }

    testImplementation(project(":testutils"))
    testImplementation(parent!!.childProjects.get("selenium")!!)
}

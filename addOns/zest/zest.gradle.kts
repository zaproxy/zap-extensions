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

version = "29"
description = "A graphical security scripting language, ZAPs macro language on steroids"

zapAddOn {
    addOnName.set("Zest - Graphical Security Scripting Language")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.7.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://github.com/zaproxy/zap-core-help/wiki/HelpAddonsZestZest")
        dependencies {
            addOns {
                register("selenium") {
                    semVer.set(" >=2.0.0 & <3.0.0 ")
                }
            }
        }
    }
}

dependencies {
    compileOnly(files("$rootDir/lib/selenium-release-3.jar"))
    implementation("com.google.code.gson:gson:2.2.2")
    implementation(files("lib/mozilla-zest-0.13.jar"))
    implementation("org.owasp.jbrofuzz:jbrofuzz-core:2.5.1") {
        // Only "jbrofuzz-core" is needed.
        setTransitive(false)
    }

    testImplementation(project(":testutils"))
    testImplementation(files("$rootDir/lib/selenium-release-3.jar"))
}

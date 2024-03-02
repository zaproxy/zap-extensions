import org.zaproxy.gradle.addon.AddOnStatus

description = "Forced browsing of files and directories using code from the OWASP DirBuster tool"

zapAddOn {
    addOnName.set("Forced Browse")
    addOnStatus.set(AddOnStatus.BETA)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/forced-browse/")

        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.23.0 & < 2.0.0")
                }
            }
        }
    }
}

dependencies {
    zapAddOn("commonlib")

    testImplementation(project(":testutils"))
}

spotless {
    javaWith3rdPartyFormatted(project, listOf("src/main/java/com/sittinglittleduck/**/*.java"))
}

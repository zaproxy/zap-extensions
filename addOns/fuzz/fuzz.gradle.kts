import org.zaproxy.gradle.addon.AddOnStatus

description = "Advanced fuzzer for manual testing"

zapAddOn {
    addOnName.set("Fuzzer")
    addOnStatus.set(AddOnStatus.BETA)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/fuzzer/")
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

    implementation("com.natpryce:snodge:2.1.2.2")
    implementation("org.owasp.jbrofuzz:jbrofuzz-core:2.5.1") {
        // Only "jbrofuzz-core" is needed.
        setTransitive(false)
    }
    implementation("com.github.mifmif:generex:1.0.2")

    testImplementation(project(":testutils"))
}

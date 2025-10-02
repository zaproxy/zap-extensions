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

    implementation(libs.fuzz.snodge)
    implementation(libs.fuzz.jbrofuzzCore) {
        // Only "jbrofuzz-core" is needed.
        setTransitive(false)
    }
    implementation(libs.fuzz.rgxgen)

    testImplementation(project(":testutils"))
}

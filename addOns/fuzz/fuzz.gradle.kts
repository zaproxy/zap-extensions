import org.zaproxy.gradle.addon.AddOnStatus

description = "Advanced fuzzer for manual testing"

zapAddOn {
    addOnName.set("Fuzzer")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.12.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/fuzzer/")
    }
}

dependencies {
    implementation("com.natpryce:snodge:2.1.2.2")
    implementation("org.owasp.jbrofuzz:jbrofuzz-core:2.5.1") {
        // Only "jbrofuzz-core" is needed.
        setTransitive(false)
    }
    implementation("com.github.mifmif:generex:1.0.2")

    testImplementation(project(":testutils"))
}

import org.zaproxy.gradle.addon.AddOnStatus

version = "11"
description = "Advanced fuzzer for manual testing"

tasks.withType<JavaCompile> {
    options.compilerArgs = options.compilerArgs - "-Werror"
}

zapAddOn {
    addOnName.set("AdvFuzzer")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.7.0")

    manifest {
        semVer.set("2.0.1")
        author.set("ZAP Dev Team")
        url.set("https://github.com/zaproxy/zap-core-help/wiki/HelpAddonsFuzzConcepts")
        dependencies {
            addOns {
                register("zest")
            }
        }
    }
}

dependencies {
    compileOnly(parent!!.childProjects.get("zest")!!)
    implementation("com.natpryce:snodge:2.1.2.2")
    implementation("org.owasp.jbrofuzz:jbrofuzz-core:2.5.1") {
        // Only "jbrofuzz-core" is needed.
        setTransitive(false)
    }
    implementation(files("lib/generex-0.0.5-SNAPSHOT.jar"))
    implementation("dk.brics.automaton:automaton:1.11-8")

    testImplementation(project(":testutils"))
    testImplementation(parent!!.childProjects.get("zest")!!)
}

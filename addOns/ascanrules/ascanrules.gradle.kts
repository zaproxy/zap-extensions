import org.zaproxy.gradle.addon.AddOnStatus

description = "The release status Active Scanner rules"

zapAddOn {
    addOnName.set("Active scanner rules")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.11.1")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/active-scan-rules/")

        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.9.0 & < 2.0.0")
                }
            }
        }
    }
}

dependencies {
    compileOnly(parent!!.childProjects.get("commonlib")!!)
    implementation("com.googlecode.java-diff-utils:diffutils:1.3.0")
    implementation("org.bitbucket.mstrobel:procyon-compilertools:0.5.36")

    testImplementation(parent!!.childProjects.get("commonlib")!!)
    testImplementation(parent!!.childProjects.get("commonlib")!!.sourceSets.test.get().output)
    testImplementation(project(":testutils"))
}

spotless {
    javaWith3rdPartyFormatted(project, listOf(
        "src/**/BufferOverflowScanRule.java",
        "src/**/CrlfInjectionScanRule.java",
        "src/**/DirectoryBrowsingScanRule.java",
        "src/**/FormatStringScanRule.java",
        "src/**/ParameterTamperScanRule.java",
        "src/**/ServerSideIncludeScanRule.java"))
}

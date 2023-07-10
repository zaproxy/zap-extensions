import org.zaproxy.gradle.addon.AddOnStatus

description = "The beta status Active Scanner rules"

zapAddOn {
    addOnName.set("Active scanner rules (beta)")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.12.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/active-scan-rules-beta/")

        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.13.0 & < 2.0.0")
                }
                register("network") {
                    version.set(">= 0.3.0")
                }
                register("oast") {
                    version.set(">= 0.7.0")
                }
                register("database") {
                    version.set(">= 0.1.0")
                }
            }
        }
    }
}

dependencies {
    compileOnly(parent!!.childProjects.get("commonlib")!!)
    compileOnly(parent!!.childProjects.get("database")!!)
    compileOnly(parent!!.childProjects.get("network")!!)
    compileOnly(parent!!.childProjects.get("oast")!!)

    implementation("com.googlecode.java-diff-utils:diffutils:1.3.0")
    implementation("org.jsoup:jsoup:1.14.3")

    testImplementation(parent!!.childProjects.get("commonlib")!!)
    testImplementation(parent!!.childProjects.get("commonlib")!!.sourceSets.test.get().output)
    testImplementation(parent!!.childProjects.get("database")!!)
    testImplementation(parent!!.childProjects.get("network")!!)
    testImplementation(parent!!.childProjects.get("oast")!!)
    testImplementation(project(":testutils"))
    testImplementation("org.apache.commons:commons-lang3:3.12")
}

spotless {
    javaWith3rdPartyFormatted(
        project,
        listOf(
            "src/**/IntegerOverflowScanRule.java",
        ),
    )
}

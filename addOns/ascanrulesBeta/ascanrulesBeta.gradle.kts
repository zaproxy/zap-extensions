import org.zaproxy.gradle.addon.AddOnStatus

description = "The beta status Active Scanner rules"

zapAddOn {
    addOnName.set("Active scanner rules (beta)")
    addOnStatus.set(AddOnStatus.BETA)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/active-scan-rules-beta/")

        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.17.0 & < 2.0.0")
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

tasks.named("compileJava") {
    mustRunAfter(parent!!.childProjects.get("oast")!!.tasks.named("enhance"))
}

dependencies {
    zapAddOn("commonlib")
    zapAddOn("database")
    zapAddOn("network")
    zapAddOn("oast")

    implementation("com.googlecode.java-diff-utils:diffutils:1.3.0")
    implementation("org.jsoup:jsoup:1.17.2")

    testImplementation(parent!!.childProjects.get("commonlib")!!.sourceSets.test.get().output)
    testImplementation(project(":testutils"))
}

spotless {
    javaWith3rdPartyFormatted(
        project,
        listOf(
            "src/**/IntegerOverflowScanRule.java",
        ),
    )
}

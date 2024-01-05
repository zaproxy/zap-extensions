import org.zaproxy.gradle.addon.AddOnStatus

description = "The release status Active Scanner rules"

zapAddOn {
    addOnName.set("Active scanner rules")
    addOnStatus.set(AddOnStatus.RELEASE)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/active-scan-rules/")

        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.21.0 & < 2.0.0")
                }
                register("network") {
                    version.set(">= 0.3.0")
                }
                register("oast") {
                    version.set(">= 0.7.0")
                }
            }
        }

        extensions {
            register("org.zaproxy.zap.extension.ascanrules.payloader.ExtensionPayloader") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.ascanrules.payloader"))
                }
                dependencies {
                    addOns {
                        register("custompayloads") {
                            version.set(">= 0.9.0 & < 1.0.0")
                        }
                    }
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
    zapAddOn("custompayloads")
    zapAddOn("network")
    zapAddOn("oast")

    implementation("com.googlecode.java-diff-utils:diffutils:1.3.0")
    implementation("org.bitbucket.mstrobel:procyon-compilertools:0.6.0")

    testImplementation(parent!!.childProjects.get("commonlib")!!.sourceSets.test.get().output)
    testImplementation(project(":testutils"))
}

spotless {
    javaWith3rdPartyFormatted(
        project,
        listOf(
            "src/**/BufferOverflowScanRule.java",
            "src/**/CrlfInjectionScanRule.java",
            "src/**/DirectoryBrowsingScanRule.java",
            "src/**/FormatStringScanRule.java",
            "src/**/ParameterTamperScanRule.java",
            "src/**/ServerSideIncludeScanRule.java",
        ),
    )
}

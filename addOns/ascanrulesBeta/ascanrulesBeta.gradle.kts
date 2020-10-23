import org.zaproxy.gradle.addon.AddOnStatus

version = "32"
description = "The beta quality Active Scanner rules"

zapAddOn {
    addOnName.set("Active scanner rules (beta)")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/active-scan-rules-beta/")

        dependencies {
            addOns {
                register("commonlib")
            }
        }

        extensions {
            register("org.zaproxy.zap.extension.ascanrulesBeta.payloader.ExtensionPayloader") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.ascanrulesBeta.payloader"))
                }
                dependencies {
                    addOns {
                        register("custompayloads") {
                            version.set("0.9.*")
                        }
                    }
                }
            }
        }
    }
}

dependencies {
    compileOnly(parent!!.childProjects.get("commonlib")!!)
    compileOnly(parent!!.childProjects.get("custompayloads")!!)

    implementation("com.googlecode.java-diff-utils:diffutils:1.3.0")
    implementation("org.jsoup:jsoup:1.13.1")

    testImplementation(parent!!.childProjects.get("commonlib")!!)
    testImplementation(parent!!.childProjects.get("commonlib")!!.sourceSets.test.get().output)
    testImplementation(parent!!.childProjects.get("custompayloads")!!)
    testImplementation(project(":testutils"))
    testImplementation("org.apache.commons:commons-lang3:3.11")
}

spotless {
    javaWith3rdPartyFormatted(project, listOf("**/IntegerOverflowScanRule.java"))
}

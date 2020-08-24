import org.zaproxy.gradle.addon.AddOnStatus

version = "30"
description = "The release quality Passive Scanner rules"

zapAddOn {
    addOnName.set("Passive scanner rules")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/passive-scan-rules/")

        dependencies {
            addOns {
                register("commonlib")
            }
        }

        extensions {
            register("org.zaproxy.zap.extension.pscanrules.payloader.ExtensionPayloader") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.pscanrules.payloader"))
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
    implementation("com.shapesecurity:salvation:2.7.2")
    compileOnly(parent!!.childProjects.get("commonlib")!!)
    compileOnly(parent!!.childProjects.get("custompayloads")!!)

    testImplementation(parent!!.childProjects.get("commonlib")!!)
    testImplementation(parent!!.childProjects.get("custompayloads")!!)
    testImplementation(project(":testutils"))
    testImplementation("org.apache.commons:commons-lang3:3.9")
}

spotless {
    javaWith3rdPartyFormatted(project, listOf(
        "**/InfoPrivateAddressDisclosureScanRule.java",
        "**/InfoSessionIdUrlScanRule.java"))
}

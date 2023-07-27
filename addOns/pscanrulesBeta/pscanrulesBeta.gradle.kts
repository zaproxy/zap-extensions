import org.zaproxy.gradle.addon.AddOnStatus

description = "The beta status Passive Scanner rules"

zapAddOn {
    addOnName.set("Passive scanner rules (beta)")
    addOnStatus.set(AddOnStatus.BETA)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/passive-scan-rules-beta/")

        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.10.0 & < 2.0.0")
                }
            }
        }
        extensions {
            register("org.zaproxy.zap.extension.pscanrulesBeta.payloader.ExtensionPayloader") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.pscanrulesBeta.payloader"))
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

dependencies {
    zapAddOn("commonlib")
    zapAddOn("custompayloads")

    testImplementation(project(":testutils"))
}

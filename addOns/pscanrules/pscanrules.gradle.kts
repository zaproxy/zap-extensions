import org.zaproxy.gradle.addon.AddOnStatus

description = "The release status Passive Scanner rules"

zapAddOn {
    addOnName.set("Passive scanner rules")
    addOnStatus.set(AddOnStatus.RELEASE)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/passive-scan-rules/")

        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.17.0 & < 2.0.0")
                }
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
                            version.set(">= 0.9.0 & < 1.0.0")
                        }
                    }
                }
            }
        }
    }
}

dependencies {
    implementation("com.google.re2j:re2j:1.7")
    implementation("org.htmlunit:htmlunit-csp:4.0.0")

    zapAddOn("commonlib")
    zapAddOn("custompayloads")

    testImplementation(project(":testutils"))
}

spotless {
    javaWith3rdPartyFormatted(
        project,
        listOf(
            "src/**/InfoPrivateAddressDisclosureScanRule.java",
            "src/**/InfoSessionIdUrlScanRule.java",
        ),
    )
}

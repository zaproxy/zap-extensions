description = "The alpha status Active Scanner rules"

zapAddOn {
    addOnName.set("Active scanner rules (alpha)")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/active-scan-rules-alpha/")

        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.40.0 & < 2.0.0")
                }
                register("client") {
                    version.set(">=0.7.0")
                }
                register("network") {
                    version.set(">=0.2.0")
                }
                register("selenium") {
                    version.set(">=15.0.0")
                }
            }
        }

        extensions {
            register("org.zaproxy.zap.extension.ascanrulesAlpha.scripts.ExtensionAscanRulesAlphaScripts") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.ascanrulesAlpha.scripts"))
                }
                dependencies {
                    addOns {
                        register("scripts")
                        register("graaljs")
                    }
                }
            }
        }
    }
}

dependencies {
    zapAddOn("commonlib")
    zapAddOn("client")
    zapAddOn("network")
    zapAddOn("selenium")
    compileOnly(parent!!.project("client"))
    compileOnly(parent!!.project("selenium"))
    testImplementation(project(":testutils"))
    testImplementation(project(":addOns:graaljs"))
    testImplementation(project(":addOns:scripts"))
    testImplementation(parent!!.childProjects.get("graaljs")!!.sourceSets.test.get().output)
}

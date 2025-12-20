description = "The alpha status Active Scanner rules"

zapAddOn {
    addOnName.set("Active scanner rules (alpha)")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/active-scan-rules-alpha/")

        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.38.0 & < 2.0.0")
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

tasks.named("compileJava") {
    mustRunAfter(parent!!.childProjects.get("oast")!!.tasks.named("enhance"))
}

dependencies {
    zapAddOn("commonlib")

    testImplementation(project(":testutils"))
    testImplementation(project(":addOns:graaljs"))
    testImplementation(project(":addOns:scripts"))
    testImplementation(parent!!.childProjects.get("graaljs")!!.sourceSets.test.get().output)
}

import org.zaproxy.gradle.addon.AddOnStatus

description = "Technology detection using various fingerprints and identifiers."

zapAddOn {
    addOnName.set("Technology Detection")
    addOnStatus.set(AddOnStatus.RELEASE)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/technology-detection/")
        extensions {
            register("org.zaproxy.zap.extension.wappalyzer.automation.ExtensionWappalyzerAutomation") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.wappalyzer.automation"))
                }
                dependencies {
                    addOns {
                        register("automation") {
                            version.set(">=0.31.0")
                        }
                    }
                }
            }
        }
        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.17.0 & < 2.0.0")
                }
                register("pscan") {
                    version.set(">= 0.1.0 & < 1.0.0")
                }
            }
        }
    }

    apiClientGen {
        api.set("org.zaproxy.zap.extension.wappalyzer.TechApi")
        messages.set(file("src/main/resources/org/zaproxy/zap/extension/wappalyzer/resources/Messages.properties"))
    }
}

dependencies {
    zapAddOn("automation")
    zapAddOn("commonlib")
    zapAddOn("pscan")

    compileOnly(libs.log4j.core)

    implementation(libs.wappalyzer.re2j)
    implementation(libs.wappalyzer.jsvg)
    implementation(libs.wappalyzer.jsoup)

    testImplementation(project(":testutils"))
}

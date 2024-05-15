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
            }
        }
    }

    apiClientGen {
        api.set("org.zaproxy.zap.extension.wappalyzer.WappalyzerAPI")
        messages.set(file("src/main/resources/org/zaproxy/zap/extension/wappalyzer/resources/Messages.properties"))
    }
}

dependencies {
    zapAddOn("automation")
    zapAddOn("commonlib")

    compileOnly(libs.log4j.core)

    implementation("com.google.re2j:re2j:1.7")
    implementation("com.github.weisj:jsvg:1.4.0")
    implementation("org.jsoup:jsoup:1.17.2")

    testImplementation(project(":testutils"))
}

import org.zaproxy.gradle.addon.AddOnStatus

description = "Technology detection using Wappalyzer: wappalyzer.com"

zapAddOn {
    addOnName.set("Wappalyzer - Technology Detection")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.11.1")

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
                            version.set(">=0.4.0")
                        }
                    }
                }
            }
        }
        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.7.0 & < 2.0.0")
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
    compileOnly(parent!!.childProjects.get("automation")!!)
    compileOnly(parent!!.childProjects.get("commonlib")!!)

    implementation("com.google.re2j:re2j:1.6")

    val batikVersion = "1.14"
    implementation("org.apache.xmlgraphics:batik-anim:$batikVersion")
    implementation("org.apache.xmlgraphics:batik-bridge:$batikVersion")
    implementation("org.apache.xmlgraphics:batik-ext:$batikVersion")
    implementation("org.apache.xmlgraphics:batik-gvt:$batikVersion")
    implementation("org.apache.xmlgraphics:batik-util:$batikVersion")

    implementation("org.jsoup:jsoup:1.14.3")

    testImplementation(parent!!.childProjects.get("commonlib")!!)
    testImplementation(project(":testutils"))
}

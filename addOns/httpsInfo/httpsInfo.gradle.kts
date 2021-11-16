description = "Displays HTTPS configuration information."

zapAddOn {
    addOnName.set("HttpsInfo")
    zapVersion.set("2.11.0")
    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/https-info-add-on/")
        extensions {
            register("org.zaproxy.zap.extension.httpsinfo.automation.ExtensionHttpsInfoAutomation") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.httpsinfo.automation"))
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
    }
}

dependencies {
    compileOnly(parent!!.childProjects.get("automation")!!)
    implementation("com.google.re2j:re2j:1.6")
    implementation("com.github.spoofzu:DeepViolet:5.1.16")
    implementation("org.jsoup:jsoup:1.14.3")
    val batikVersion = "1.14"
    implementation("org.apache.xmlgraphics:batik-anim:$batikVersion")
    implementation("org.apache.xmlgraphics:batik-bridge:$batikVersion")
    implementation("org.apache.xmlgraphics:batik-ext:$batikVersion")
    implementation("org.apache.xmlgraphics:batik-gvt:$batikVersion")
    implementation("org.apache.xmlgraphics:batik-util:$batikVersion")

    implementation("org.apache.logging.log4j:log4j-slf4j-impl:2.14.1") {
        // Provided by ZAP.
        exclude(group = "org.apache.logging.log4j")
    }
}

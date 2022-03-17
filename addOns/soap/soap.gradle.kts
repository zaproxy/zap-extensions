description = "Imports and scans WSDL files containing SOAP endpoints."

zapAddOn {
    addOnName.set("SOAP Support")
    zapVersion.set("2.11.1")

    manifest {
        author.set("Alberto (albertov91) + ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/soap-support/")

        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.5.0 & < 2.0.0")
                }
            }
        }

        extensions {
            register("org.zaproxy.zap.extension.soap.automation.ExtensionSoapAutomation") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.soap.automation"))
                }
                dependencies {
                    addOns {
                        register("automation") {
                            version.set(">=0.12.0")
                        }
                    }
                }
            }
        }
    }

    apiClientGen {
        api.set("org.zaproxy.zap.extension.soap.SoapAPI")
        messages.set(file("src/main/resources/org/zaproxy/zap/extension/soap/resources/Messages.properties"))
    }
}

dependencies {
    compileOnly(parent!!.childProjects.get("automation")!!)
    compileOnly(parent!!.childProjects.get("commonlib")!!)
    implementation("com.predic8:soa-model-core:1.6.3")
    implementation("com.sun.xml.messaging.saaj:saaj-impl:2.0.1")
    implementation("jakarta.xml.soap:jakarta.xml.soap-api:2.0.1")
    implementation("org.apache.logging.log4j:log4j-slf4j-impl:2.17.2") {
        // Provided by ZAP.
        exclude(group = "org.apache.logging.log4j")
    }
    // Dependency of "com.predic8:soa-model-core:1.6.3".
    implementation("org.codehaus.groovy:groovy:3.0.9")

    testImplementation(parent!!.childProjects.get("automation")!!)
    testImplementation(parent!!.childProjects.get("commonlib")!!)
    testImplementation(project(":testutils"))
}

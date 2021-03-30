version = "7"
description = "Imports and scans WSDL files containing SOAP endpoints."

zapAddOn {
    addOnName.set("SOAP Support")
    zapVersion.set("2.10.0")

    manifest {
        author.set("Alberto (albertov91) + ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/soap-support/")
        extensions {
            register("org.zaproxy.zap.extension.soap.automation.ExtensionSoapAutomation") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.soap.automation"))
                }
                dependencies {
                    addOns {
                        register("automation") {
                            version.set("0.*")
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
    implementation("com.predic8:soa-model-core:1.6.0")
    implementation("jakarta.xml.soap:jakarta.xml.soap-api:1.4.2")
    implementation("com.sun.xml.messaging.saaj:saaj-impl:1.5.2")

    testImplementation(parent!!.childProjects.get("automation")!!)
    testImplementation(project(":testutils"))
}

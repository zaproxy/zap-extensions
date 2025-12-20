import org.zaproxy.gradle.addon.AddOnStatus

description = "Imports and scans WSDL files containing SOAP endpoints."

zapAddOn {
    addOnName.set("SOAP Support")
    addOnStatus.set(AddOnStatus.BETA)

    manifest {
        author.set("Alberto (albertov91) + ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/soap-support/")

        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.36.0 & < 2.0.0")
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
                            version.set(">=0.31.0")
                        }
                    }
                }
            }

            register("org.zaproxy.zap.extension.soap.spider.ExtensionSoapSpider") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.soap.spider"))
                }
                dependencies {
                    addOns {
                        register("spider") {
                            version.set(">=0.1.0")
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
    zapAddOn("automation")
    zapAddOn("commonlib")
    zapAddOn("spider")

    implementation(libs.soap.soaModelCore)
    implementation(libs.soap.saajImpl)
    implementation(libs.soap.jakartaXmlSoapApi)
    implementation(libs.log4j.slf4j)

    testImplementation(project(":testutils"))
}

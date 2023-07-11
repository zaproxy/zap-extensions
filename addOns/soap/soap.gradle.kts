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
                            version.set(">=0.24.0")
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

            register("org.zaproxy.zap.extension.soap.formhandler.ExtensionSoapFormHandler") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.soap.formhandler"))
                }
                dependencies {
                    addOns {
                        register("formhandler") {
                            version.set(">=6.0.0 & < 7.0.0")
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
    compileOnly(parent!!.childProjects.get("formhandler")!!)
    compileOnly(parent!!.childProjects.get("spider")!!)
    implementation("com.predic8:soa-model-core:2.0.1")
    implementation("com.sun.xml.messaging.saaj:saaj-impl:3.0.0")
    implementation("jakarta.xml.soap:jakarta.xml.soap-api:3.0.0")
    implementation(libs.log4j.slf4j) {
        // Provided by ZAP.
        exclude(group = "org.apache.logging.log4j")
    }

    testImplementation(parent!!.childProjects.get("automation")!!)
    testImplementation(parent!!.childProjects.get("commonlib")!!)
    testImplementation(parent!!.childProjects.get("formhandler")!!)
    testImplementation(parent!!.childProjects.get("spider")!!)
    testImplementation(project(":testutils"))
}

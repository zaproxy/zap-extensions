version = "28"
description = "The alpha quality Active Scanner rules"

zapAddOn {
    addOnName.set("Active scanner rules (alpha)")
    zapVersion.set("2.8.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/active-scan-rules-alpha/")
        extensions {
            register("org.zaproxy.zap.extension.ascanrulesAlpha.payloader.ExtensionPayloader") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.ascanrulesAlpha.payloader"))
                }
                dependencies {
                    addOns {
                        register("custompayloads") {
                            version.set("0.9.*")
                        }
                    }
                }
            }
        }
    }
}

dependencies {
    compileOnly(parent!!.childProjects.get("custompayloads")!!)

    implementation(project(":sharedutils"))

    testImplementation(parent!!.childProjects.get("custompayloads")!!)
    testImplementation(project(":testutils"))
}

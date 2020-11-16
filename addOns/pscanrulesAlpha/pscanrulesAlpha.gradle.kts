version = "30"
description = "The alpha quality Passive Scanner rules"

zapAddOn {
    addOnName.set("Passive scanner rules (alpha)")
    zapVersion.set("2.10.0")

    manifest {
        author.set("ZAP Dev Team")
        notBeforeVersion.set("2.10.0")
        extensions {
            register("org.zaproxy.zap.extension.pscanrulesAlpha.payloader.ExtensionPayloader") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.pscanrulesAlpha.payloader"))
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
        url.set("https://www.zaproxy.org/docs/desktop/addons/passive-scan-rules-alpha/")
    }
}

repositories {
    maven {
        url = uri("https://oss.sonatype.org/content/repositories/snapshots/")
    }
}

dependencies {
    zap("org.zaproxy:zap:2.10.0-20201111.162919-2")

    compileOnly(parent!!.childProjects.get("custompayloads")!!)

    testImplementation(parent!!.childProjects.get("custompayloads")!!)
    testImplementation(project(":testutils"))
}

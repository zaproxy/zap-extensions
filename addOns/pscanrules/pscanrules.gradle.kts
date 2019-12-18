import org.zaproxy.gradle.addon.AddOnStatus

version = "26"
description = "The release quality Passive Scanner rules"

zapAddOn {
    addOnName.set("Passive scanner rules")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.8.0")

    manifest {
        author.set("ZAP Dev Team")
        extensions {
            register("org.zaproxy.zap.extension.pscanrules.payloader.ExtensionPayloader") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.pscanrules.payloader"))
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
    implementation("com.shapesecurity:salvation:2.7.0")
    compileOnly(parent!!.childProjects.get("custompayloads")!!)

    testImplementation(parent!!.childProjects.get("custompayloads")!!)
    testImplementation(project(":testutils"))
    testImplementation("org.apache.commons:commons-lang3:3.7")
}

spotless {
    javaWith3rdPartyFormatted(project, listOf(
        "**/TestInfoPrivateAddressDisclosure.java",
        "**/TestInfoSessionIdURL.java"))
}

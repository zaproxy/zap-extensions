import org.zaproxy.gradle.addon.AddOnStatus

version = "28"
description = "The beta quality Active Scanner rules"

zapAddOn {
    addOnName.set("Active scanner rules (beta)")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.8.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/active-scan-rules-beta/")
        extensions {
            register("org.zaproxy.zap.extension.ascanrulesBeta.payloader.ExtensionPayloader") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.ascanrulesBeta.payloader"))
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

    implementation("com.googlecode.java-diff-utils:diffutils:1.2.1")
    implementation("org.jsoup:jsoup:1.7.2")
    implementation(project(":sharedutils"))

    testImplementation(parent!!.childProjects.get("custompayloads")!!)
    testImplementation(project(":testutils"))
    testImplementation("org.apache.commons:commons-lang3:3.5")
}

spotless {
    javaWith3rdPartyFormatted(project, listOf("**/IntegerOverflow.java"))
}

import org.zaproxy.gradle.addon.AddOnStatus

version = "26"
description = "Provides a tab which allows you to quickly test a target application"

zapAddOn {
    addOnName.set("Quick Start")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.7.0")

    manifest {
        author.set("ZAP Dev Team")
        extensions {
            register("org.zaproxy.zap.extension.quickstart.launch.ExtensionQuickStartLaunch") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.quickstart.launch"))
                }
                dependencies {
                    addOns {
                        register("selenium") {
                            semVer.set("2.*")
                        }
                    }
                }
            }
        }
    }
}

dependencies {
    compileOnly(parent!!.childProjects.get("selenium")!!)
}

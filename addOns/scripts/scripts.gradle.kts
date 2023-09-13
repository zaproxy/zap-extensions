import org.zaproxy.gradle.addon.AddOnStatus

description = "Supports all JSR 223 scripting languages"

zapAddOn {
    addOnName.set("Script Console")
    addOnStatus.set(AddOnStatus.RELEASE)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/script-console/")
        extensions {
            register("org.zaproxy.zap.extension.scripts.automation.ExtensionScriptAutomation") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.scripts.automation"))
                }
                dependencies {
                    addOns {
                        register("automation") {
                            version.set(">=0.31.0")
                        }
                        register("commonlib")
                    }
                }
            }
        }
    }
}

spotless {
    java {
        target(
            fileTree(projectDir) {
                include("src/**/*.java")
                // 3rd-party code.
                exclude("src/**/JScrollPopupMenu.java")
            },
        )
    }
}

dependencies {
    zapAddOn("automation")
    zapAddOn("commonlib")

    testImplementation(project(":testutils"))
}

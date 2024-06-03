import org.zaproxy.gradle.addon.AddOnStatus

description = "Supports all JSR 223 scripting languages"

zapAddOn {
    addOnName.set("Script Console")
    addOnStatus.set(AddOnStatus.RELEASE)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/script-console/")
        // Don't search the add-on classes to prevent the inclusion
        // of some scan rules which are loaded at runtime.
        classpath.setFrom(files())
        extensions {
            register("org.zaproxy.zap.extension.scripts.ExtensionScriptsUI")
            register("org.zaproxy.zap.extension.scripts.automation.ExtensionScriptAutomation") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.scripts.automation"))
                }
                dependencies {
                    addOns {
                        register("automation") {
                            version.set(">=0.31.0")
                        }
                    }
                }
            }
        }
        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">=1.25.0")
                }
            }
        }
        ascanrules {
            register("org.zaproxy.zap.extension.scripts.scanrules.ScriptsActiveScanner")
        }
        pscanrules {
            register("org.zaproxy.zap.extension.scripts.scanrules.ScriptsPassiveScanner")
        }
    }

    apiClientGen {
        api.set("org.zaproxy.zap.extension.scripts.ScriptApi")
        messages.set(file("src/main/resources/org/zaproxy/zap/extension/scripts/resources/Messages.properties"))
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

    implementation("net.bytebuddy:byte-buddy:1.14.13")

    testImplementation(project(":testutils"))
}

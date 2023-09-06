import org.zaproxy.gradle.addon.AddOnStatus

description = "Easy way to replace strings in requests and responses."

zapAddOn {
    addOnName.set("Replacer")
    addOnStatus.set(AddOnStatus.RELEASE)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/replacer/")
        extensions {
            register("org.zaproxy.zap.extension.replacer.automation.ExtensionReplacerAutomation") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.replacer.automation"))
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

    apiClientGen {
        api.set("org.zaproxy.zap.extension.replacer.ReplacerAPI")
        messages.set(file("src/main/resources/org/zaproxy/zap/extension/replacer/resources/Messages.properties"))
    }
}

dependencies {
    zapAddOn("automation")
    zapAddOn("commonlib")
    testImplementation(project(":testutils"))
}

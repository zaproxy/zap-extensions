import org.zaproxy.gradle.addon.AddOnStatus

description = "Provides core passive scanning capabilities."

zapAddOn {
    addOnName.set("Passive Scanner")
    addOnStatus.set(AddOnStatus.ALPHA)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/passive-scanner/")

        helpSet {
            baseName.set("org.zaproxy.addon.pscan.help%LC%.helpset")
            localeToken.set("%LC%")
        }

        extensions {
            register("org.zaproxy.addon.pscan.automation.ExtensionPscanAutomation") {
                classnames {
                    allowed.set(listOf("org.zaproxy.addon.pscan.automation"))
                }
                dependencies {
                    addOns {
                        register("automation") {
                            version.set(">=0.42.0")
                        }
                    }
                }
            }
        }
    }

    apiClientGen {
        api.set("org.zaproxy.addon.pscan.PassiveScanApi")
    }
}

dependencies {
    zapAddOn("automation")
    zapAddOn("commonlib")

    testImplementation(project(":testutils"))
}

version = "10"
description = "DOM XSS Active scanner rule"

zapAddOn {
    addOnName.set("DOM XSS Active scanner rule")
    zapVersion.set("2.7.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/dom-xss-active-scan-rule/")
        // Don't search the add-on classes to prevent the inclusion
        // of the scanner, it's added/removed by the extension.
        classpath.setFrom(files())
        extensions {
            register("org.zaproxy.zap.extension.domxss.ExtensionDomXSS")
        }
        dependencies {
            addOns {
                register("selenium") {
                    version.set("15.*")
                }
            }
        }
    }
}

dependencies {
    compileOnly(parent!!.childProjects.get("selenium")!!)
}

description = "Adds the Eval Villain extension to Firefox when launched from ZAP."

zapAddOn {
    addOnName.set("Eval Villain")
    zapVersion.set("2.11.1")

    manifest {
        author.set("Dennis Goodlett and the ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/eval-villain/")

        helpSet {
            baseName.set("org.zaproxy.addon.evalvillain.resources.help%LC%.helpset")
            localeToken.set("%LC%")
        }

        dependencies {
            addOns {
                register("selenium") {
                    version.set(">=15.5.0")
                }
            }
        }
    }
}

crowdin {
    configuration {
        val resourcesPath = "org/zaproxy/addon/${zapAddOn.addOnId.get()}/resources/"
        file.set(file("$rootDir/gradle/crowdin-help-only.yml"))
        tokens.put("%helpPath%", resourcesPath)
    }
}

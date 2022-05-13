import org.zaproxy.gradle.addon.AddOnStatus

description = "All of the add-ons just containing release, beta and alpha status scan rules"

zapAddOn {
    addOnName.set("Collection: Scan Rules Pack")
    addOnStatus.set(AddOnStatus.ALPHA)
    zapVersion.set("2.11.1")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/collection-scan-rules-pack/")

        dependencies {
            addOns {
                register("ascanrules")
                register("ascanrulesAlpha")
                register("ascanrulesBeta")
                register("domxss")
                register("pscanrules")
                register("pscanrulesAlpha")
                register("pscanrulesBeta")
                register("retire")
            }
        }

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}

crowdin {
    configuration {
        file.set(file("$rootDir/gradle/crowdin-help-only.yml"))
        tokens.put("%helpPath%", "")
    }
}

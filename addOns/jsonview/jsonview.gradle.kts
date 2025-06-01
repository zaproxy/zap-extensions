description = "Adds a view that shows JSON messages nicely formatted"

zapAddOn {
    addOnName.set("JSON View")

    manifest {
        author.set("Juha Kivekäs")
        url.set("https://www.zaproxy.org/docs/desktop/addons/json-view/")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }

        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.16.0 & < 2.0.0")
                }
            }
        }
    }
}

crowdin {
    configuration {
        file.set(file("$rootDir/gradle/crowdin-help-only.yml"))
        tokens.put("%helpPath%", "")
    }
}

dependencies {
    zapAddOn("commonlib")

    testImplementation(project(":testutils"))
}

description = "Adds a view that shows JSON messages nicely formatted"

zapAddOn {
    addOnName.set("JSON View")
    zapVersion.set("2.12.0")

    manifest {
        author.set("Juha Kivekäs")
        url.set("https://www.zaproxy.org/docs/desktop/addons/json-view/")

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

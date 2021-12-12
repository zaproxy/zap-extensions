description = "Allows to test Regular Expressions"

zapAddOn {
    addOnName.set("Regular Expression Tester")
    zapVersion.set("2.11.1")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/regular-expression-tester/")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}

crowdin {
    configuration {
        tokens.put("%helpPath%", "")
    }
}

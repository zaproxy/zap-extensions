version = "2"
description = "Allows to test Regular Expressions"

zapAddOn {
    addOnName.set("Regular Expression Tester")
    zapVersion.set("2.8.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/regular-expression-tester/")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}

version = "8"
description = "Allows you to highlight strings in the request and response tabs."

zapAddOn {
    addOnName.set("Highlighter")
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/highlighter/")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}

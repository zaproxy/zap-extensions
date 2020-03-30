version = "0.2.0"
description = "Allows to save content of HTTP messages as XML"

zapAddOn {
    addOnName.set("Save XML Message")
    zapVersion.set("2.9.0")

    manifest {
        author.set("thatsn0tmysite")
        url.set("https://www.zaproxy.org/docs/desktop/addons/save-xml-message/")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}

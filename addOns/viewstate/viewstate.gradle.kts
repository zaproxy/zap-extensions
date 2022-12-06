description = "ASP/JSF ViewState Decoder and Editor"

zapAddOn {
    addOnName.set("ViewState")
    zapVersion.set("2.12.0")

    manifest {
        author.set("Calum Hutton")
        url.set("https://www.zaproxy.org/docs/desktop/addons/viewstate/")

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

description = "Request numbered panel."

zapAddOn {
    addOnName.set("Requester")
    zapVersion.set("2.11.1")

    manifest {
        author.set("Surikato")
        url.set("https://www.zaproxy.org/docs/desktop/addons/requester/")

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

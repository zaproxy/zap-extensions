version = "2"
description = "Adds a view that shows JSON messages nicely formatted"

zapAddOn {
    addOnName.set("JSON View")
    zapVersion.set("2.7.0")

    manifest {
        author.set("Juha Kivekäs")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}

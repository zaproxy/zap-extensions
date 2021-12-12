description = "Allows the user to view a call graph of the selected resources"

zapAddOn {
    addOnName.set("Call Graph")
    zapVersion.set("2.11.1")

    manifest {
        author.set("Colm O'Flaherty")
        url.set("https://www.zaproxy.org/docs/desktop/addons/call-graph/")

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

dependencies {
    implementation("org.tinyjee.jgraphx:jgraphx:3.4.1.3")
}

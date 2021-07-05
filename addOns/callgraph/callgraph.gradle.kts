description = "Allows the user to view a call graph of the selected resources"

zapAddOn {
    addOnName.set("Call Graph")
    zapVersion.set("2.10.0")

    manifest {
        author.set("Colm O'Flaherty")
        url.set("https://www.zaproxy.org/docs/desktop/addons/call-graph/")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}

dependencies {
    implementation("org.tinyjee.jgraphx:jgraphx:3.4.1.3")
}

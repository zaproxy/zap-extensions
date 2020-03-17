version = "5"
description = "Allows the user to view a call graph of the selected resources"

zapAddOn {
    addOnName.set("Call Graph")
    zapVersion.set("2.9.0")

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
    implementation("jgraph:jgraph:5.13.0.0")
    implementation("org.tinyjee.jgraphx:jgraphx:2.0.0.1")
}

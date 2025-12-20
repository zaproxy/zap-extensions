description = "Allows the user to view a call graph of the selected resources"

zapAddOn {
    addOnName.set("Call Graph")

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
    implementation(libs.callgraph.jgraphx)
}

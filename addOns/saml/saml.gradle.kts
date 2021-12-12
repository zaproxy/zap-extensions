description = "Detect, Show, Edit, Fuzz SAML requests"

zapAddOn {
    addOnName.set("SAML Support")
    zapVersion.set("2.11.1")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/saml-support/")

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
    implementation("org.glassfish.jaxb:jaxb-runtime:2.3.2")
}

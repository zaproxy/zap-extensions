version = "9"
description = "Detect, Show, Edit, Fuzz SAML requests"

zapAddOn {
    addOnName.set("SAML Extension")
    zapVersion.set("2.5.0")

    manifest {
        author.set("ZAP Dev Team")
    }
}

dependencies {
    implementation("org.glassfish.jaxb:jaxb-runtime:2.3.2")
}

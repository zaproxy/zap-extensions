version = "2"
description = "Lists vulnerabilities from known databases"

zapAddOn {
    addOnName.set("VulnCheck")
    zapVersion.set("2.5.0")

    manifest {
        author.set("ZAP Dev Team")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}

dependencies {
    implementation("com.googlecode.json-simple:json-simple:1.1.1")
    implementation("org.jsoup:jsoup:1.7.2")
}

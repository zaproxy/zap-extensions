version = "3"
description = "Adds support for AMF messages"

repositories {
    maven("https://repo.spring.io/ext-release-local/")
}

zapAddOn {
    addOnName.set("AMF Support")
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/amf-support/")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}

val blazedsVersion = "4.0.0.14931"

dependencies {
    implementation("com.adobe.blazeds:blazeds-common:$blazedsVersion")
    implementation("com.adobe.blazeds:blazeds-core:$blazedsVersion")
}

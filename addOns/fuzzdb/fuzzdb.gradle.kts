import org.zaproxy.gradle.addon.AddOnStatus

plugins {
    eclipse
}

eclipse {
    classpath {
        // Prevent compilation of zapHomeFiles.
        sourceSets = listOf()
    }
}

version = "8"
description = "FuzzDB files which can be used with the ZAP fuzzer"

zapAddOn {
    addOnName.set("FuzzDB Files")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/fuzzdb-files/")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}

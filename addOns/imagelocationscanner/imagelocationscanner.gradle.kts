import org.zaproxy.gradle.addon.AddOnStatus

version = "2"
description = "Image Location and Privacy Passive Scanner"

zapAddOn {
    addOnName.set("Image Location and Privacy Scanner")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.9.0")

    manifest {
        author.set("Veggiespam and the ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/image-location-and-privacy-scanner/")
    }
}

dependencies {
    implementation("com.adobe.xmp:xmpcore:6.0.6")
    implementation("com.drewnoakes:metadata-extractor:2.13.0")

    testImplementation(project(":testutils"))
}

spotless {
    java {
        target(fileTree(projectDir) {
            include("**/*.java")
            // Ignore ILS classes.
            exclude("**/com/veggiespam/**", "**/ImageLocationScanner.java")
        })
    }
}

import org.zaproxy.gradle.addon.AddOnStatus

version = "2"
description = "Image Location and Privacy Passive Scanner"

zapAddOn {
    addOnName.set("Image Location and Privacy Scanner")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.7.0")

    manifest {
        author.set("Veggiespam and the ZAP Dev Team")
    }
}

dependencies {
    implementation("com.adobe.xmp:xmpcore:5.1.3")
    implementation("com.drewnoakes:metadata-extractor:2.10.1")

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
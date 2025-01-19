import org.zaproxy.gradle.addon.AddOnStatus

description = "Image Location and Privacy Passive Scanner"

zapAddOn {
    addOnName.set("Image Location and Privacy Scanner")
    addOnStatus.set(AddOnStatus.BETA)

    manifest {
        author.set("Jay Ball (veggiespam) and the ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/image-location-and-privacy-scanner/")

        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.6.0 & < 2.0.0")
                }
            }
        }
    }
}

dependencies {
    zapAddOn("commonlib")

    implementation("com.adobe.xmp:xmpcore:6.0.6")
    implementation("com.drewnoakes:metadata-extractor:2.13.0")

    testImplementation(project(":testutils"))
}

spotless {
    javaWith3rdPartyFormatted(
        project,
        listOf(
            "src/**/ImageLocationScanRule.java",
        ),
        listOf("src/**/com/veggiespam/**"),
    )
}

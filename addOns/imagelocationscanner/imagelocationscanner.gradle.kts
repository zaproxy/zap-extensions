import org.zaproxy.gradle.addon.AddOnStatus

description = "Image Location and Privacy Passive Scanner"

zapAddOn {
    addOnName.set("Image Location and Privacy Scanner")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.11.1")

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
    compileOnly(parent!!.childProjects.get("commonlib")!!)

    implementation("com.adobe.xmp:xmpcore:6.0.6")
    implementation("com.drewnoakes:metadata-extractor:2.13.0")

    testImplementation(parent!!.childProjects.get("commonlib")!!)
    testImplementation(project(":testutils"))
}

spotless {
    java {
        target(fileTree(projectDir) {
            include("src/**/*.java")
            // Ignore ILS classes.
            exclude("src/**/com/veggiespam/**", "src/**/ImageLocationScanRule.java")
        })
    }
}

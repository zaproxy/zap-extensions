import org.zaproxy.gradle.addon.AddOnStatus

version = "8"
description = "Tools to add functionality to the tree view."

zapAddOn {
    addOnName.set("TreeTools")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.5.0")

    manifest {
        author.set("Carl Sampson")
    }
}

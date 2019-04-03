version = "6"
description = "Gives the possibility of defining a sequence of requests to be scanned."

zapAddOn {
    addOnName.set("Sequence")
    zapVersion.set("2.7.0")

    manifest {
        author.set("ZAP Dev Team")
        dependencies {
            addOns {
                register("zest")
            }
        }
    }
}

description = "Gives the possibility of defining a sequence of requests to be scanned."

zapAddOn {
    addOnName.set("Sequence")
    zapVersion.set("2.11.1")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/sequence-scanner/")
        dependencies {
            addOns {
                register("zest")
            }
        }
    }
}

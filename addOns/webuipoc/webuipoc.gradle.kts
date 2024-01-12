description = "A Proof of Concept add-on for potential ZAP web based UIs."

zapAddOn {
    addOnName.set("Web UI PoC")

    manifest {
        author.set("ZAP Dev Team")

        dependencies {
            addOns {
                register("network") {
                    version.set(">=0.13.0")
                }
            }
        }
    }
}

dependencies {
    zapAddOn("network")
}

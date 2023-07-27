description = "An add-on to help with development of ZAP."

zapAddOn {
    addOnName.set("Dev Add-on")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/dev-add-on/")

        dependencies {
            addOns {
                register("network") {
                    version.set(">=0.7.0")
                }
            }
        }
    }
}

dependencies {
    zapAddOn("network")
}

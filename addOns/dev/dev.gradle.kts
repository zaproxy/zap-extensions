description = "An add-on to help with development of ZAP."

zapAddOn {
    addOnName.set("Dev Add-on")
    zapVersion.set("2.12.0")

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
    compileOnly(parent!!.childProjects.get("network")!!)
    testImplementation(parent!!.childProjects.get("network")!!)
}

version = "0.0.1"
description = "A new description."

zapAddOn {
    addOnName.set("My AddOn")
    zapVersion.set("2.10.0")

    manifest {
        author.set("ZAP Dev Team")

        dependencies{
            addOns{
                register("client") {
                    version.set("0.21.0")
                }
            }
        }
    }
}
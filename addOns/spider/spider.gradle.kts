description = "Add supplemental parsing functionality to the spider."

zapAddOn {
    addOnName.set("Spider")
    zapVersion.set("2.11.1")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/spider/")
    }
}

dependencies {
    testImplementation(project(":testutils"))
}

plugins {
    id("org.openjfx.javafxplugin") version "0.0.13"
}

description = "Adds an option to render HTML responses like a browser"

javafx {
    version = "11"
    modules("javafx.swing", "javafx.web")
    configuration = "compileOnly"
}

zapAddOn {
    addOnName.set("Browser View")
    zapVersion.set("2.11.1")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/browser-view/")
    }
}

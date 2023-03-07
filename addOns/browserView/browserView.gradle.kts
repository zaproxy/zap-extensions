plugins {
    id("org.openjfx.javafxplugin") version "0.0.13"
}

description = "Adds an option to render HTML responses like a browser"

javafx {
    version = if (System.getProperty("os.arch")!!.contains("aarch64")) "17" else "11"
    modules("javafx.swing", "javafx.web")
    configuration = "compileOnly"
}

zapAddOn {
    addOnName.set("Browser View")
    zapVersion.set("2.12.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/browser-view/")
    }
}

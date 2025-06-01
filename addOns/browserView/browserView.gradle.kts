plugins {
    id("org.openjfx.javafxplugin") version "0.1.0"
}

description = "Adds an option to render HTML responses like a browser"

javafx {
    version = if (System.getProperty("os.arch")!!.contains("aarch64")) "17" else "11"
    modules("javafx.swing", "javafx.web")
    configuration = "compileOnly"
}

zapAddOn {
    addOnName.set("Browser View")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/browser-view/")
    }
}

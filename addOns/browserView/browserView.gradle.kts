description = "Adds an option to render HTML responses like a browser"

if (JavaVersion.current() <= JavaVersion.VERSION_1_10) {
    try {
        Class.forName("javafx.application.Platform")
    } catch (e: ClassNotFoundException) {
        logger.warn("JavaFX not found, the add-on will not be built.")
        tasks.configureEach {
            if (name != "clean") {
                enabled = false
            }
        }
    }
} else {
    val javaFxVersion = "11"
    // Shouldn't matter which platform is compiled against.
    val javaFxPlatform = "linux"

    dependencies {
        compileOnly("org.openjfx:javafx-base:$javaFxVersion:$javaFxPlatform")
        compileOnly("org.openjfx:javafx-graphics:$javaFxVersion:$javaFxPlatform")
        compileOnly("org.openjfx:javafx-web:$javaFxVersion:$javaFxPlatform")
        compileOnly("org.openjfx:javafx-swing:$javaFxVersion:$javaFxPlatform")
    }
}

zapAddOn {
    addOnName.set("Browser View")
    zapVersion.set("2.11.1")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/browser-view/")
    }
}

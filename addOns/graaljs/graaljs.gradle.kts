import org.zaproxy.gradle.addon.AddOnStatus

version = "0.2.0"
description = "Provides the GraalVM JavaScript engine for ZAP scripting."

zapAddOn {
    addOnName.set("GraalVM JavaScript")
    addOnStatus.set(AddOnStatus.ALPHA)
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }

        bundledLibs {
            libs.from(configurations.runtimeClasspath)
        }
    }
}

dependencies {
    val graalJsVersion = "20.2.0"
    implementation("org.graalvm.js:js:$graalJsVersion")
    implementation("org.graalvm.js:js-scriptengine:$graalJsVersion")
}

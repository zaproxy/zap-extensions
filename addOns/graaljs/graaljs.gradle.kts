import org.zaproxy.gradle.addon.AddOnStatus

description = "Provides the GraalVM JavaScript engine for ZAP scripting."

zapAddOn {
    addOnName.set("GraalVM JavaScript")
    addOnStatus.set(AddOnStatus.ALPHA)
    zapVersion.set("2.11.0")

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

crowdin {
    configuration {
        tokens.put("%helpPath%", "")
    }
}

dependencies {
    val graalJsVersion = "21.3.0"
    implementation("org.graalvm.js:js:$graalJsVersion")
    implementation("org.graalvm.js:js-scriptengine:$graalJsVersion")
    implementation("org.javadelight:delight-graaljs-sandbox:0.1.2")

    testImplementation(project(":testutils"))
}

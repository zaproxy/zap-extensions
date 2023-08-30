import org.zaproxy.gradle.addon.AddOnStatus

description = "Provides the GraalVM JavaScript engine for ZAP scripting."

zapAddOn {
    addOnName.set("GraalVM JavaScript")
    addOnStatus.set(AddOnStatus.ALPHA)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/graalvm-javascript/")

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
    val graalJsVersion = "22.3.3"
    implementation("org.graalvm.js:js:$graalJsVersion")
    implementation("org.graalvm.js:js-scriptengine:$graalJsVersion")
    implementation("org.javadelight:delight-graaljs-sandbox:0.1.2")

    testImplementation(project(":testutils"))
}

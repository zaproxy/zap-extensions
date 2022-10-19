import org.zaproxy.gradle.addon.AddOnStatus

description = "A common library, for use by other add-ons."

zapAddOn {
    addOnName.set("Common Library")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.11.1")

    manifest {
        author.set("ZAP Dev Team")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(8))
    }
    sourceCompatibility = null
    targetCompatibility = null
}

crowdin {
    configuration {
        file.set(file("$rootDir/gradle/crowdin-help-only.yml"))
        tokens.put("%helpPath%", "")
    }
}

dependencies {
    implementation("commons-io:commons-io:2.11.0")
    implementation("org.apache.commons:commons-csv:1.9.0")
    implementation("org.apache.commons:commons-collections4:4.4")

    testImplementation(project(":testutils"))
}

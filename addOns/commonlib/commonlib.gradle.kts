import org.zaproxy.gradle.addon.AddOnStatus

description = "A common library, for use by other add-ons."

zapAddOn {
    addOnName.set("Common Library")
    addOnStatus.set(AddOnStatus.RELEASE)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/common-library/")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}

crowdin {
    configuration {
        file.set(file("$projectDir/gradle/crowdin.yml"))
        tokens.put("%helpPath%", "")
    }
}

dependencies {
    api(platform(libs.commonlib.jackson.bom))
    api(libs.commonlib.jackson.databind)
    api(libs.commonlib.jackson.dataformat.xml)
    api(libs.commonlib.jackson.dataformat.yaml)
    api(libs.commonlib.jackson.datatype.jdk8)
    api(libs.commonlib.jackson.datatype.jsr310)

    implementation(libs.commonlib.apache.commons.io)
    implementation(libs.commonlib.apache.commons.csv)
    implementation(libs.commonlib.apache.commons.collections4)

    testImplementation(project(":testutils"))
}

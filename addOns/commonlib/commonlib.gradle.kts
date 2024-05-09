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

        extensions {
            register("org.zaproxy.addon.commonlib.formhandler.ExtensionCommonlibFormHandler") {
                classnames {
                    allowed.set(listOf("org.zaproxy.addon.commonlib.formhandler"))
                }
                dependencies {
                    addOns {
                        register("formhandler") {
                            version.set(">=6.0.0 & < 7.0.0")
                        }
                    }
                }
            }
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
    zapAddOn("formhandler")

    api(platform("com.fasterxml.jackson:jackson-bom:2.17.0"))
    api("com.fasterxml.jackson.core:jackson-databind")
    api("com.fasterxml.jackson.dataformat:jackson-dataformat-xml")
    api("com.fasterxml.jackson.dataformat:jackson-dataformat-yaml")
    api("com.fasterxml.jackson.datatype:jackson-datatype-jdk8")
    api("com.fasterxml.jackson.datatype:jackson-datatype-jsr310")

    implementation("commons-io:commons-io:2.16.1")
    implementation("org.apache.commons:commons-csv:1.10.0")
    implementation("org.apache.commons:commons-collections4:4.4")

    testImplementation(project(":testutils"))
}

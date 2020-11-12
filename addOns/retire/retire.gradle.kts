import org.zaproxy.gradle.addon.AddOnStatus

version = "0.6.0"
description = "Retire.js"

zapAddOn {
    addOnName.set("Retire.js")
    addOnStatus.set(AddOnStatus.RELEASE)

    manifest {
        author.set("Nikita Mundhada and the ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/retire.js/")
        zapVersion.set("2.10.0")
        bundle {
            baseName.set("org.zaproxy.addon.retire.resources.Messages")
            prefix.set("retire")
        }
        helpSet {
            baseName.set("org.zaproxy.addon.retire.resources.help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}

repositories {
    maven {
        url = uri("https://oss.sonatype.org/content/repositories/snapshots/")
    }
}

dependencies {
    zap("org.zaproxy:zap:2.10.0-20201111.162919-2")

        implementation("com.google.code.gson:gson:2.8.6")

        testImplementation(project(":testutils"))
}

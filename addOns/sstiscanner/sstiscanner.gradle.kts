import org.zaproxy.gradle.addon.AddOnStatus

version = "1"
description = "Scans for server side template injection"

repositories {
    maven(url = uri("https://oss.sonatype.org/content/repositories/snapshots/"))
}

zapAddOn {
    addOnName.set("Server Side Template Injection Scanner")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.9.0")

    manifest {
        author.set("Diogo Silva (DiogoMrSilva)")
        extensions {
            register("org.zaproxy.zap.extension.sstiscanner.ExtensionSSTiPlugin")
        }
        dependencies {
            addOns {
                register("ascanrules")
            }
        }
    }
}

dependencies {
    compileOnly(parent!!.childProjects.get("commonlib")!!)
    compileOnly(parent!!.childProjects.get("ascanrules")!!)

    testImplementation(parent!!.childProjects.get("ascanrules")!!)
    testImplementation(project(":testutils"))
    testImplementation("org.apache.commons:commons-lang3:3.9")
}

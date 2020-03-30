import org.zaproxy.gradle.addon.AddOnStatus

version = "10"
description = "Forced browsing of files and directories using code from the OWASP DirBuster tool"

tasks.withType<JavaCompile> {
    options.compilerArgs = options.compilerArgs - "-Werror"
}

zapAddOn {
    addOnName.set("Forced Browse")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/forced-browse/")
    }
}

dependencies {
    testImplementation(project(":testutils"))
}

spotless {
    javaWith3rdPartyFormatted(project, listOf("**/main/java/com/sittinglittleduck/**/*.java"))
}

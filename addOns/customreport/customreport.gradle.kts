version = "5"
description = "New HTML report module allows users to customize report content."

zapAddOn {
    addOnName.set("CustomReport")
    zapVersion.set("2.5.0")

    manifest {
        author.set("Chienli Ma")
    }
}

spotless {
    java {
        target(fileTree(projectDir) {
            include("**/*.java")
            exclude("**/ReportGenerator.java", "**/ReportLastScan.java")
        })
    }
}

version = "0"
description = "An extension to implement SQLMap."

zapAddOn {
    addOnName.set("sqlmap")
    zapVersion.set("2.10.0")

    manifest {
        author.set("Mario Bajer")
    }
}

dependencies {
    implementation("com.google.code.gson:gson:2.8.6")
}

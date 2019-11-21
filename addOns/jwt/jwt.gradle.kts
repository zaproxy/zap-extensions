version = "1"
description = "Detect, Show, Edit, Fuzz JWT requests"

zapAddOn {
    addOnName.set("JWT Extension")
    zapVersion.set("2.5.0")

    manifest {
        author.set("ZAP Dev Team")
    }
}

dependencies {
    implementation("io.jsonwebtoken:jjwt-api:0.10.7")
    runtime("io.jsonwebtoken:jjwt-impl:0.10.7")
    // Uncomment the next line if you want to use RSASSA-PSS (PS256, PS384, PS512) algorithms:
    //'org.bouncycastle:bcprov-jdk15on:1.60',
    runtime("io.jsonwebtoken:jjwt-jackson:0.10.7")
}

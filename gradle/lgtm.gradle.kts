import org.zaproxy.gradle.tasks.DownloadWebDriver

// Build tweaks when running by LGTM

System.getenv("LGTM_SRC")?.let {

    allprojects {
        // Don't download WebDrivers, the downloads fail more often than not.
        tasks.withType(DownloadWebDriver::class).configureEach {
            enabled = false
        }
    }

}
package com.hsauth;

public class Main {
    public static void main(String[] args) {
        System.out.println("[*] Initializing HS DEVS AUTH Java SDK...");

        HSAUTH auth = new HSAUTH(
            "MyApp",
            "your_app_identifier_here",
            "1.0",
            "https://hsauth.mujahid.xyz/api/1.3/"
        );

        if (!auth.init()) {
            System.err.println("[!] Failed to initialize with HS DEVS AUTH server.");
            return;
        }

        System.out.println("[+] Connected to HS DEVS AUTH!");
        System.out.println("[+] Application Version: " + auth.appData.get("version"));

        // Authenticate with License Key
        String licenseKey = "HSAUTH-XXXX-XXXX-XXXX-XXXX";
        if (auth.license(licenseKey)) {
            System.out.println("[+] License authenticated successfully!");
            System.out.println("[+] HWID: " + auth.userData.get("hwid"));

            // Remote variable
            String varVal = auth.var("my_secret");
            System.out.println("[+] Remote Variable Value: " + varVal);
        } else {
            System.err.println("[!] License activation failed.");
        }
    }
}

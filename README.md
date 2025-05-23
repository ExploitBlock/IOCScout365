# Office 365 IOC Extractor (IOCScout365)

IOCScout365 is a Chrome extension designed to help identify Indicators of Compromise (IOCs) on suspected Office 365 phishing pages. It analyzes the current page for suspicious elements, scripts, domains, and other patterns commonly found in phishing kits.

## Features

*   **Brand Detection:** Identifies if the page is attempting to impersonate Microsoft/Office 365.
*   **Critical IOC Extraction:**
    *   Form submission URLs (where credentials might be sent).
    *   Suspicious external and inline scripts.
    *   Suspicious domains linked or referenced.
*   **Other IOCs:**
    *   All external links and scripts.
    *   All unique domains found on the page.
    *   IFrames and their sources.
    *   DNS prefetch and preconnect links.
    *   Meta redirect tags.
*   **Phishing Kit Signals:** Detects common file names, comments, and code structures used in known Office 365 phishing kits.
*   **Obfuscation Signals:** Identifies use of Base64 encoding, CryptoJS, and other obfuscation techniques in scripts.
*   **Anti-Analysis Techniques:** Detects common methods used to hinder analysis (e.g., DevTools blocking, context menu disabling).
*   **Downloadable Report:** Allows users to download the extracted IOCs in a JSON format.

## Installation

1.  Clone this repository or download the source code.
2.  Open Chrome and navigate to `chrome://extensions`.
3.  Enable "Developer mode" using the toggle in the top right corner.
4.  Click "Load unpacked" and select the directory where you cloned/downloaded the extension files.

## Usage

1.  Navigate to a webpage you suspect might be an Office 365 phishing attempt.
2.  Click the IOCScout365 extension icon in your Chrome toolbar.
3.  The popup will display a summary of detected IOCs.
4.  Click the "Download JSON" button to save a detailed report.

## Development Notes

*   The content script (`content_script.js`) performs the core IOC extraction logic.
*   The popup (`popup.html` and `popup.js`) displays the results and handles user interaction.
*   `manifest.json` defines the extension's permissions, scripts, and icons.
*   The extension requires permissions to access web content and `file://` URLs for local testing.

## Disclaimer

This tool is intended for security professionals and researchers. Always exercise caution when analyzing potentially malicious websites. Do not enter real credentials into suspected phishing pages.

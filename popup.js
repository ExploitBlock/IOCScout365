// This script will handle the logic for the popup
document.addEventListener('DOMContentLoaded', function() {
  const iocList = document.getElementById('iocList');
  const downloadJsonBtn = document.getElementById('downloadJsonBtn');
  const iocBanner = document.getElementById('iocBanner');
  let currentIocs = null; // To store the fetched IOCs for download
  let previousIocs = null; // To compare for new IOCs

  // Helper: Sanitize strings to prevent XSS
  function sanitizeString(str) {
    if (!str) return '';
    return String(str)
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // Helper: Deep compare two IOC objects for new content
  function hasNewIocs(oldIocs, newIocs) {
    if (!oldIocs) return true;
    // Compare all array fields in criticalIOCs and otherIOCs
    function flatSet(iocObj) {
      if (!iocObj) return [];
      return Object.values(iocObj).flat();
    }
    const oldCritical = new Set(flatSet(oldIocs.criticalIOCs));
    const newCritical = new Set(flatSet(newIocs.criticalIOCs));
    const oldOther = new Set(flatSet(oldIocs.otherIOCs));
    const newOther = new Set(flatSet(newIocs.otherIOCs));
    // If newCritical or newOther has any value not in oldCritical/oldOther, return true
    for (const val of newCritical) if (!oldCritical.has(val)) return true;
    for (const val of newOther) if (!oldOther.has(val)) return true;
    // Also check signals
    const signalKeys = ['phishingKitSignals','obfuscationSignals','antiAnalysisSignals'];
    for (const key of signalKeys) {
      const oldArr = (oldIocs[key]||[]), newArr = (newIocs[key]||[]);
      if (newArr.length > oldArr.length) return true;
      for (const val of newArr) if (!oldArr.includes(val)) return true;
    }
    return false;
  }

  // Show a banner for new IOCs
  function showBanner(msg) {
    iocBanner.textContent = msg;
    iocBanner.style.display = 'block';
    setTimeout(() => { iocBanner.style.display = 'none'; }, 2500);
  }

  // Listen for IOC_UPDATE messages from the content script for real-time updates
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'IOC_UPDATE' && message.data) {
      if (hasNewIocs(currentIocs, message.data)) {
        showBanner('New IOCs detected!');
      }
      previousIocs = currentIocs;
      currentIocs = message.data;
      updatePopup(currentIocs);
    }
  });


  // Helper to sanitize strings for textContent
  function sanitizeString(str) {
    if (!str) return '';
    return String(str)
      .replace(/</g, '<')
      .replace(/>/g, '>')
      .replace(/"/g, '"')
      .replace(/'/g, "'");
  }

  // Request IOCs from the content script when the popup is opened (secure message passing)
  chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
    if (!tabs[0] || !tabs[0].id) {
      console.error("Could not get active tab ID.");
      iocList.innerHTML = '';
      const li = document.createElement('li');
      li.textContent = 'Error: Could not access active tab.';
      iocList.appendChild(li);
      return;
    }
    chrome.tabs.sendMessage(
      tabs[0].id,
      { type: "GET_IOCS" },
      (response) => {
        if (chrome.runtime.lastError) {
          console.error("Error sending message: ", chrome.runtime.lastError.message);
          iocList.innerHTML = '';
          const li = document.createElement('li');
          li.textContent = 'Error: ' + sanitizeString(chrome.runtime.lastError.message);
          iocList.appendChild(li);
          return;
        }
        if (response && !response.error) {
          if (hasNewIocs(currentIocs, response)) {
            showBanner('New IOCs detected!');
          }
          previousIocs = currentIocs;
          currentIocs = response;
          updatePopup(currentIocs);
        } else {
          iocList.innerHTML = '';
          const li = document.createElement('li');
          li.textContent = 'No IOCs found or an error occurred during extraction.';
          iocList.appendChild(li);
          console.warn("Response problematic: ", response);
        }
      }
    );
  });

  function updatePopup(iocs) {
    iocList.innerHTML = ''; // Clear previous list

    if (!iocs || Object.keys(iocs).length === 0) {
      iocList.innerHTML = '<li>No IOCs detected on this page.</li>';
      return;
    }

    // Minimal display for demonstration (add your real display logic here)
    for (const key in iocs) {
      const listItem = document.createElement('li');
      listItem.textContent = key + ': ' + JSON.stringify(iocs[key]);
      iocList.appendChild(listItem);
    }
  }

}); // <-- Close DOMContentLoaded event listener
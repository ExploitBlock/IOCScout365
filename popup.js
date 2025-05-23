// This script will handle the logic for the popup
document.addEventListener('DOMContentLoaded', function() {
  const iocList = document.getElementById('iocList');
  const downloadJsonBtn = document.getElementById('downloadJsonBtn');
  const iocBanner = document.getElementById('iocBanner');
  let currentIocs = null; // To store the fetched IOCs for download
  let previousIocs = null; // To compare for new IOCs

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

    // Display Page Info
    if (iocs.pageInfo) {
      const pageHeader = document.createElement('h4');
      pageHeader.textContent = 'Page Information';
      iocList.appendChild(pageHeader);
      for (const key in iocs.pageInfo) {
        const listItem = document.createElement('li');
        listItem.textContent = `${key.charAt(0).toUpperCase() + key.slice(1)}: ${iocs.pageInfo[key]}`;
        iocList.appendChild(listItem);
      }
    }

    // Display Detected Brand
    if (iocs.detectedBrand) {
      const brandHeader = document.createElement('h4');
      brandHeader.textContent = 'Detected Brand';
      iocList.appendChild(brandHeader);
      const brandItem = document.createElement('li');
      brandItem.textContent = iocs.detectedBrand;
      iocList.appendChild(brandItem);
    }

    // Display Critical IOCs
    if (iocs.criticalIOCs && Object.keys(iocs.criticalIOCs).some(key => iocs.criticalIOCs[key] && iocs.criticalIOCs[key].length > 0)) {
      const criticalHeader = document.createElement('h4');
      criticalHeader.textContent = 'Critical IOCs';
      iocList.appendChild(criticalHeader);
      for (const type in iocs.criticalIOCs) {
        if (iocs.criticalIOCs[type] && iocs.criticalIOCs[type].length > 0) {
          iocs.criticalIOCs[type].forEach(ioc => {
            const listItem = document.createElement('li');
            listItem.textContent = `${type}: ${ioc}`;
            iocList.appendChild(listItem);
          });
        }
      }
    }

    // Display Other IOCs (simplified for brevity in popup)
    if (iocs.otherIOCs && Object.keys(iocs.otherIOCs).some(key => iocs.otherIOCs[key] && iocs.otherIOCs[key].length > 0)) {
      const otherHeader = document.createElement('h4');
      otherHeader.textContent = 'Other IOCs (Summary)';
      iocList.appendChild(otherHeader);
      for (const type in iocs.otherIOCs) {
        if (iocs.otherIOCs[type] && iocs.otherIOCs[type].length > 0) {
          const listItem = document.createElement('li');
          listItem.textContent = `${type}: ${iocs.otherIOCs[type].length} found (see JSON for details)`;
          iocList.appendChild(listItem);
        }
      }
    }

    // Display Signals (Phishing Kit, Obfuscation, Anti-Analysis)
    const signalTypes = ['phishingKitSignals', 'obfuscationSignals', 'antiAnalysisSignals'];
    signalTypes.forEach(signalKey => {
      if (iocs[signalKey] && iocs[signalKey].length > 0) {
        const header = document.createElement('h4');
        header.textContent = signalKey.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase()); // Format title
        iocList.appendChild(header);
        iocs[signalKey].forEach(signal => {
          const listItem = document.createElement('li');
          listItem.textContent = signal;
          iocList.appendChild(listItem);
        });
      }
    });

  }

  downloadJsonBtn.addEventListener('click', function() {
    if (currentIocs) {
      const jsonData = JSON.stringify(currentIocs, null, 2);
      const blob = new Blob([jsonData], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      // Sanitize filename from page title or use domain
      let filename = 'ioc_report.json';
      if (currentIocs.pageInfo && currentIocs.pageInfo.title) {
        filename = currentIocs.pageInfo.title.replace(/[^a-z0-9_\-\.]/gi, '_').substring(0, 50) + '.json';
      } else if (currentIocs.pageInfo && currentIocs.pageInfo.domain) {
        filename = currentIocs.pageInfo.domain.replace(/[^a-z0-9_\-\.]/gi, '_') + '.json';
      }
      a.href = url;
      a.download = filename;
      document.body.appendChild(a); // Required for Firefox
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } else {
      alert("No IOC data to download. Please wait for IOCs to load.");
    }
  });

});



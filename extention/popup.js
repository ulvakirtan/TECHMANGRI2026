console.log("popup.js loaded");

function populateTabInfo() {
    if (!chrome || !chrome.tabs || typeof chrome.tabs.query !== "function") {
        console.warn("chrome.tabs.query is unavailable in this context.");
        return;
    }

    chrome.tabs.query(
        {
            active: true,
            currentWindow: true
        },
        function(tabs) {
            try {
                const tab = Array.isArray(tabs) && tabs.length > 0 ? tabs[0] : null;
                if (!tab) {
                    const websiteEl = document.getElementById("website");
                    if (websiteEl) {
                        websiteEl.textContent = "No active tab found";
                    }
                    return;
                }

                const url = typeof tab.url === "string" && tab.url ? tab.url : "N/A";
                const title = typeof tab.title === "string" && tab.title ? tab.title : "N/A";
                const favIconUrl = typeof tab.favIconUrl === "string" && tab.favIconUrl ? tab.favIconUrl : "";
                const id = tab.id;
                const windowId = tab.windowId;
                const index = tab.index;
                const pinned = tab.pinned;
                const audible = tab.audible;
                const mutedInfo = tab.mutedInfo;
                const autoDiscardable = tab.autoDiscardable;
                const discarded = tab.discarded;
                const incognito = tab.incognito;

                console.log({ id, windowId, index, pinned, audible, mutedInfo, autoDiscardable, discarded, incognito });

                const websiteEl = document.getElementById("website");
                const titleEl = document.getElementById("title");
                const protocolEl = document.getElementById("protocol");
                const faviconEl = document.getElementById("favicon");

                if (websiteEl) {
                    websiteEl.textContent = url;
                }

                if (titleEl) {
                    titleEl.textContent = title;
                }

                if (protocolEl) {
                    try {
                        protocolEl.textContent = new URL(url).protocol;
                    } catch (error) {
                        protocolEl.textContent = "N/A";
                    }
                }

                if (faviconEl) {
                    faviconEl.src = favIconUrl;
                    faviconEl.alt = title;
                }
            } catch (error) {
                console.error("Failed to populate tab info:", error);
            }
        }
    );
}

const getCurrentTabButton = document.getElementById("getCurrentTab");
if (getCurrentTabButton) {
    getCurrentTabButton.addEventListener("click", populateTabInfo);
}

populateTabInfo();
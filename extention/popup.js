console.log("popup.js loaded");
chrome.tabs.query(
    {
        active: true,
        currentWindow: true
    },
    function(tabs){
        console.log(tabs);
    }
);
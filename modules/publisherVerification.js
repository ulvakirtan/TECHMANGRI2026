// modules/publisherVerification.js
// Module 4: Publisher Verification.

import { KNOWN_PUBLISHERS } from "./config.js";

const SUSPICIOUS_NAME_PATTERNS = [
  /setup[_-]?(free|crack|patched|keygen)/i,
  /\bcrack(ed)?\b/i,
  /\bkeygen\b/i,
  /\bpatch(er)?\b/i,
  /\bportable[_-]?activator\b/i
];

export function verifyPublisher({ domain, filename, isExecutable, category }, extraTrustedDomains = [], publisherList = KNOWN_PUBLISHERS) {
  const activePublishers = Array.isArray(publisherList) && publisherList.length > 0 ? publisherList : KNOWN_PUBLISHERS;
  const matchedPublisher = activePublishers.find(p =>
    p.domains.some(d => domain === d || domain.endsWith(`.${d}`))
  );

  const flaggedFilename = SUSPICIOUS_NAME_PATTERNS.some(rx => rx.test(filename));


  let score;
  let confidence;
  let claimedPublisher = null;

  if (flaggedFilename) {
    score = 5;
    confidence = "low";
  } else if (matchedPublisher) {
    claimedPublisher = matchedPublisher.name;
    score = 100;
    confidence = "domain_correlated";
  } else if (!isExecutable && category !== "script") {
    // Non-executables and non-scripts from unknown domains carry low risk for publisher checks
    score = 80;
    confidence = "not_applicable";
  } else {
    score = 55;
    confidence = "unknown";
  }

  return {
    publisherVerificationScore: score,
    claimedPublisher,
    confidence,
    flaggedFilename,
    limitation:
      "Browser-side heuristic — real Authenticode/codesign validation " +
      "requires OS-level inspection."
  };
}


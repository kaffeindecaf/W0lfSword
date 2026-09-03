# WebKit download-gap verification on current main (2026-09-03)

Fresh fetch of Source/WebKit + Source/WebCore files from WebKit main
(2026-09-03) re-verifying BB-047/052. Evidence:
~/Desktop/ios-bounty-hunt/reports/webkit-main-verify-20260903/
(6 fixing-commit patches + download-gaps.txt with line excerpts).

## What is still open on current main

1. startDownload / convertMainResourceLoadToDownload
   (Source/WebKit/NetworkProcess/NetworkConnectionToWebProcess.cpp:812-835)
   validate ONLY firstPartyForCookies. No scheme check anywhere in the
   download IPC boundary. A compromised WebContent process can send
   StartDownload for a file:// URL and the network process accepts it.
   The CVE-2026-43725 fix (ccf0c4874cb2) added protocolIsInHTTPFamily
   checks to loadImageForDecoding and dataTaskWithRequest only, not to
   the download path (verified: the fixed sites carry the check, the
   download sites do not).

2. DownloadManager::startDownload explicitly supports blob: URLs
   (protocolIsBlob branch resolving blobFileReferences via filesInBlob,
   no origin or registration validation beyond topOrigin passthrough).
   The CVE-2026-43701 data:-download guard (f23ffb5a8450: WebPageProxy
   receivedNavigationResponsePolicyDecision + DocumentLoader
   disallowDataRequest at :1106-1112) covers data: only. A blob: URL
   registered with attacker bytes and an unshowable MIME survives both
   guards and lands on disk through the download path.

3. Summary: both BB-052 gaps are still present on main as of
   2026-09-03. The fixes landed after the 26.6 release fork, so current
   shipping Safari predates them; the blob:/file: gaps are unfixed on
   main itself.

## What is closed (negative result)

BB-047 item 3 sibling family (shadow-element raw-owner UAF): hardened
across the board on main. DataListButtonElement, AutoFillButtonElement,
SpinButtonElement, DateTimeEditElement/DateTimeFieldElement all use
WeakPtr + removeOwner (AbstractRefCountedAndCanMakeWeakPtr owner bases);
TextFieldInputType::removeShadowSubtree calls removeOwner for both
autoFillButton and dataListDropdownIndicator. SearchFieldCancelButton /
SearchFieldResultsButton / DetailsMarkerControl were refactored into
owner-free elements (TextControlInnerElements) or removed. Select family
has no owner pattern. The be0872059370 fix family looks complete on main.

## Next lanes (unexercised this session)

- BB-047 item 1 (TransformStream type confusion, 8fd92b1021d3) and item
  2 (CSSFontFace::setStatus iterateClients UAF, 5aedb82710ba): sibling
  scan needs a tree-wide pattern search (copyToVectorOf<Ref> /
  iterateClients / unchecked dynamicDowncast). GitHub code search needs
  auth; grep.app was unreachable from this host. A sparse clone of
  WebCore/Source (or full shallow clone) unblocks it.
- Dynamic proof of the blob:/file: download gaps still needs a build
  (WebKitGTK was abandoned for disk/time in BB-052) or an on-device
  check via WebKit's IPC test API. Static evidence is the proof of
  record.

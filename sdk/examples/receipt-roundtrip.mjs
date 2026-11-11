import { CrawlCheck } from "@crawlcheck/sdk";

// Agent process: the SDK verifies preflight and attaches the receipt to the guarded GET.
export async function readWithReceipt(url) {
  const result = await new CrawlCheck().guardedFetch(url, { action: "read" });
  if (!result.proceed || !result.response?.ok) {
    throw new Error("Read did not complete: " + (result.why?.join(", ") || result.response?.status || "refused"));
  }
  return result.response;
}

// Destination process: pass a configured host for this site, independent of incoming headers.
export async function checkIncomingReceipt(request, siteHost) {
  const header = request.headers.get("CrawlCheck-Receipt");
  if (!header) return false;
  try {
    const result = await new CrawlCheck().checkReceiptHeader(header, siteHost);
    return result.accept;
  } catch {
    return false;
  }
}

if (process.argv[1] && import.meta.url === new URL(process.argv[1], "file:").href) {
  if (!process.argv[2]) throw new Error("Usage: node sdk/examples/receipt-roundtrip.mjs https://your-pilot-site.example/page");
  const response = await readWithReceipt(process.argv[2]);
  console.log("Guarded read completed:", response.status);
}

function FindProxyForURL(url, host) {
  // wireproxy's HTTP proxy only supports HTTPS, so plain http goes direct
  if (url.substring(0, 6) !== "https:") return "DIRECT";

  // Only these sites go through the proxy
  if (host === "hitomi.la" || dnsDomainIs(host, ".hitomi.la"))
    return "PROXY 192.168.1.59:8118; DIRECT";

  return "DIRECT";
}

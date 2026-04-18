/**
 * Parse and clean a domain string from user input.
 * Strips protocols, trailing slashes, paths, and whitespace.
 */
export function parseDomain(input) {
  if (!input || typeof input !== "string") return "";

  let domain = input.trim().toLowerCase();

  // Remove protocol
  domain = domain.replace(/^https?:\/\//, "");

  // Remove www. prefix (optional)
  // domain = domain.replace(/^www\./, '');

  // Remove path and query
  domain = domain.split("/")[0];
  domain = domain.split("?")[0];
  domain = domain.split("#")[0];

  // Remove port
  domain = domain.split(":")[0];

  // Remove trailing dots
  domain = domain.replace(/\.+$/, "");

  return domain;
}

/**
 * Basic domain validation
 */
export function isValidDomain(domain) {
  if (!domain) return false;
  const pattern = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;
  return pattern.test(domain);
}

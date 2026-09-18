// Minimal node:path stand-in for the browser bundle: the string operations the
// pure artifact paths can reference; separators are POSIX (the page never
// touches real paths — the fs stub refuses those calls).
export const sep = "/";
export const join = (...parts: string[]): string => parts.filter(Boolean).join("/");
export const dirname = (p: string): string => {
  const i = p.lastIndexOf("/");
  return i === -1 ? "." : p.slice(0, i) || "/";
};
export const relative = (_from: string, to: string): string => to;

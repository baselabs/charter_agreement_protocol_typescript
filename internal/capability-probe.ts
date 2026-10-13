// Private injection seam for substrate tests; omitted from package exports.
export const capabilityProbe = {
  verify(operation: () => boolean): boolean { return operation(); },
  run(_alg: string, probe: () => boolean): boolean { return probe(); },
};

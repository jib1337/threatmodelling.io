// Barrel for every type the app consumes, split by ownership:
//
//   ./librarySchema  — content of the technology & threat catalogue, which moves
//                      to its own repository and ships as a versioned release
//   ../types/app     — how this app models diagrams, risk and saved files
//
// Import from here (`data/schema`) as before; the split is an implementation
// detail so that extracting the catalogue does not churn every call site.

export * from './librarySchema';
export * from '../types/app';

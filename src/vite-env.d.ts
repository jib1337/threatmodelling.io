/// <reference types="vite/client" />

declare module '*.css' {
  const content: Record<string, string>;
  export default content;
}

// Injected by vite.config.ts — the short commit SHA of the running build.
declare const __BUILD_ID__: string;

/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Base URL of the Checkpoint Service, e.g. http://localhost:8000 */
  readonly VITE_ADF_API_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

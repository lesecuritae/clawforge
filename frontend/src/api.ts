export type Envelope<T> = {
  status: string;
  data: T;
  timestamp: string;
  pagination?: { page: number; page_size: number; total: number; has_next: boolean } | null;
  errors: string[];
};

const base = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "/api";
export const unauthorizedEvent = "clawforge:unauthorized";

export function prepareTokenRefresh(): Promise<string | null> {
  // The backend currently issues short-lived sessions without a refresh endpoint.
  // Keeping this boundary here lets a future API refresh be added without putting
  // token policy or credential handling into individual views.
  return Promise.resolve(null);
}

export async function api<T>(path: string, token?: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  headers.set("Accept", "application/json");
  if (init?.body) headers.set("Content-Type", "application/json");
  if (token) headers.set("Authorization", "Bearer " + token);
  const response = await fetch(base + path, { ...init, headers });
  const body = await response.json().catch(() => ({ errors: ["Invalid API response"] }));
  if (response.status === 401) {
    window.dispatchEvent(new Event(unauthorizedEvent));
  }
  if (!response.ok) {
    const message = Array.isArray(body?.errors) ? body.errors.join(", ") : "API request failed (" + response.status + ")";
    throw new Error(message);
  }
  return body as T;
}

export async function textApi(path: string, token?: string): Promise<string> {
  const headers = new Headers();
  headers.set("Accept", "text/plain");
  if (token) headers.set("Authorization", "Bearer " + token);
  const response = await fetch(base + path, { headers });
  if (response.status === 401) window.dispatchEvent(new Event(unauthorizedEvent));
  if (!response.ok) throw new Error("API request failed (" + response.status + ")");
  return response.text();
}

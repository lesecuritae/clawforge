import React, { useEffect, useState } from "react";
import { api, textApi, type Envelope } from "./api";

export function useApi<T>(path: string, token: string | null, fallback: T) {
  const [data, setData] = useState(fallback);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [pagination, setPagination] = useState<Envelope<T>["pagination"]>(null);
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    if (!token && path !== "/health" && path !== "/ready") { setLoading(false); return; }
    let cancelled = false;
    setLoading(true); setError(null);
    api<Envelope<T>>(path, token ?? undefined).then((response) => { if (!cancelled) { setData(response.data); setPagination(response.pagination ?? null); } }).catch((reason: unknown) => { if (!cancelled) setError(reason instanceof Error ? reason.message : "API request failed"); }).finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [path, token, revision]);
  return { data, loading, error, pagination, reload: () => setRevision((value) => value + 1) };
}

export function useTextApi(path: string, token: string | null) {
  const [data, setData] = useState(""); const [error, setError] = useState<string | null>(null);
  useEffect(() => { if (!token) return; let cancelled = false; textApi(path, token).then((value) => { if (!cancelled) setData(value); }).catch((reason: unknown) => { if (!cancelled) setError(reason instanceof Error ? reason.message : "API request failed"); }); return () => { cancelled = true; }; }, [path, token]);
  return { data, error };
}

export function Card({ title, value, hint, tone = "default" }: { title: string; value: React.ReactNode; hint?: string; tone?: string }) {
  return <section className={"card metric " + tone}><span className="eyebrow">{title}</span><strong>{value}</strong>{hint && <small>{hint}</small>}</section>;
}
export function Table({ children }: { children: React.ReactNode }) { return <div className="table-wrap"><table>{children}</table></div>; }
export function Empty({ text = "No records returned by the API." }: { text?: string }) { return <div className="empty">{text}</div>; }
export function Loading() { return <div className="empty">Loading API data…</div>; }
export function PageTitle({ eyebrow, title, subtitle }: { eyebrow: string; title: string; subtitle: string }) { return <div className="page-heading"><div><p className="eyebrow">{eyebrow}</p><h2>{title}</h2><p className="muted">{subtitle}</p></div></div>; }
export function Badge({ value }: { value: string }) { return <span className={"badge " + value.toLowerCase().replaceAll(" ", "-")}>{value}</span>; }
export function Meter({ value }: { value: number }) { return <span className="meter"><i style={{ width: Math.max(0, Math.min(100, value)) + "%" }} /><em>{value}</em></span>; }
export function formatDate(value: string) { if (!value) return "—"; const date = new Date(value); return Number.isNaN(date.valueOf()) ? value : date.toLocaleString(); }
export function dateQuery(value: string) { return value ? new Date(value).toISOString() : ""; }
export function ErrorNotice({ error }: { error: string | null }) { return error ? <div className="form-error api-error">{error}</div> : null; }
export function Pager({ page, pagination, onPage }: { page: number; pagination: Envelope<unknown>["pagination"]; onPage: (page: number) => void }) {
  if (!pagination || (pagination.total <= pagination.page_size && page === 1)) return null;
  return <div className="pager"><button disabled={page <= 1} onClick={() => onPage(page - 1)}>Previous</button><span>Page {pagination.page} · {pagination.total} records</span><button disabled={!pagination.has_next} onClick={() => onPage(page + 1)}>Next</button></div>;
}
export function SearchControls({ search, setSearch, children }: { search: string; setSearch: (value: string) => void; children?: React.ReactNode }) {
  return <div className="toolbar"><label className="search-label">Search<input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Filter current results" /></label>{children}</div>;
}

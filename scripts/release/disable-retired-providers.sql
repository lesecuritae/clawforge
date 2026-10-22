-- Retired network providers keep a registry row (history, dashboards) but no code runs them:
--   bgpview_asn : api.bgpview.io stopped resolving
--   bgpstream   : bgpstream.com resolves but accepts no TCP connection (639 consecutive failures)
-- Disable the rows so the operations view stops listing them as enabled and failing.
-- Reversible: UPDATE providers SET enabled = true WHERE id IN (...).  No row is deleted.
\set ON_ERROR_STOP on
BEGIN;
SELECT id, enabled FROM providers WHERE id IN ('bgpview_asn', 'bgpstream') ORDER BY id;
UPDATE providers SET enabled = false, updated_at = NOW()
 WHERE id IN ('bgpview_asn', 'bgpstream') AND enabled;
SELECT id, enabled FROM providers WHERE id IN ('bgpview_asn', 'bgpstream') ORDER BY id;
COMMIT;

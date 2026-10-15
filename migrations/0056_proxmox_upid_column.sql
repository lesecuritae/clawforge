-- Q2a: durable Proxmox-UPID ↔ quarantine-intent association
-- Store the observed Proxmox UPID as a new nullable column on the prepared quarantine
-- intent in the firewall_action_intents table, written in the prepare transaction,
-- before the external Proxmox task is awaited.
ALTER TABLE firewall_action_intents
    ADD COLUMN proxmox_upid TEXT NULL;

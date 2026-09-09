-- v0.12 compatibility for the public incident lifecycle vocabulary.
ALTER TABLE incident_status_history DROP CONSTRAINT IF EXISTS incident_status_history_new_status_check;
ALTER TABLE incident_status_history ADD CONSTRAINT incident_status_history_new_status_check CHECK
    (new_status IN ('open','acknowledged','detected','investigating','confirmed','mitigated','resolved','closed'));

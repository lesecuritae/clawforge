# Event backbone

The event backbone uses migration `0011_events.sql` and keeps canonical events
separate from delivery state. `events` stores the immutable event envelope;
`event_consumers` tracks service heartbeats; `event_delivery` tracks retries,
processing, and dead-letter state per consumer.

The authenticated read API is available to Administrators and Operators:

* `GET /events`
* `GET /events/{event_id}`
* `GET /events/status`

The event and delivery endpoints are internal and require a Docker Secret
service token. The notifier consumes the `notifier` delivery stream, while
`clawforge-events` consumes the `events` stream. Delivery is deduplicated by
event and consumer, retried with bounded exponential backoff, and marked
`dead` after five failed attempts. No consumer can invoke risk, policy, trust,
provider, or blocking actions.

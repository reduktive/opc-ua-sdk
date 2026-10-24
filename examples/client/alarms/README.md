# Client alarms

Tracks what is currently wrong, and acknowledges it. It talks to
[`server/alarms`](../../server/alarms/README.md).

[`client/events`](../events/README.md) receives events: something happened, and you either heard it
or you did not. An alarm has state, and that changes what a client does with it. Refreshing asks the
server to replay everything currently retained, so a client that has just connected knows what is
wrong without waiting for the next change. `AlarmConditionTracker` keeps that state for you and
answers "what is active right now?" from its own view.

## What you will learn

- Tracking conditions through `connection.alarms()`, and asking the tracker rather than
  interpreting an event stream.
- Waiting for the tracker to attach before refreshing, and why a refresh cannot happen sooner.
- That active and acknowledged are independent: an alarm can be on and seen, or off and unseen.
- That each state is doubly optional, and absent is not the same as false.
- Acknowledging a condition, and what makes it leave the operator's list.

## Prerequisites

An installed SDK, and `example_server_alarms` already running in another terminal.

## Run it

```bash
./example_client_alarms
```

## Expected output

```text
=== client/alarms ===
Track what is currently wrong, then acknowledge it.

  1. Connected to opc.tcp://127.0.0.1:<port>
  2. Refreshed: Boiler.Temperature [inactive, unacknowledged]
  3. Heated past the threshold: Boiler.Temperature [active, unacknowledged]
  4. Acknowledged: Boiler.Temperature [active, acknowledged]
  5. Cooled back down, nothing left to act on: nothing retained
  6. Closed the Session and stopped the client

OK  client/alarms
```

Step 5 is the one worth understanding. The condition does not vanish because the temperature fell —
it vanishes because it is now *neither* active *nor* unacknowledged, so there is nothing left for an
operator to do about it and the server stops retaining it. Acknowledge without cooling, or cool
without acknowledging, and it stays on the list.

## How it works

| Step | Where | SDK type |
| --- | --- | --- |
| 1 | `create_client`, `connect`, `resolve` | `ua::client::Client`, `ua::hierarchical_path` |
| 2 | `examples::alarms::await_tracker_attached` | `ua::client::EventSubscriber::info` |
| 2 | `main` | `ua::client::AlarmConditionTracker::refresh_sync` |
| 2–5 | `examples::alarms::describe`, `examples::alarms::is_set` | `ua::client::TrackedCondition`, `ua::client::TwoStateValue` |
| 3, 5 | `heat_by`, `examples::alarms::await_state` | `ua::client::TypedAccess::call_method_sync` |
| 4 | `examples::alarms::acknowledge_first` | `AlarmConditionTracker::acknowledge_sync` |
| 5 | `examples::alarms::await_cleared` | `AlarmConditionTracker::list_conditions_sync` |
| 6 | `main` | `ua::client::Connection::close_sync` |

## Make it yours

- Point it at another server with `--endpoint opc.tcp://host:port`.
- Register `on_condition_added` and `on_condition_changed` and react to transitions, instead of
  asking for a snapshot after each step. A display wants the callbacks; a script wants the snapshot.
- Read the sub-states your conditions actually carry. `suppressedState`, `silenceState`,
  `outOfServiceState` and `shelvingState` are all Optional, and a server that supports none of them
  is not a server whose alarms are all normal.
- Confirm as well as acknowledge where the workflow has two steps, using `confirm_sync`.
- Shelve a noisy alarm with `timed_shelve_sync` or `one_shot_shelve_sync` rather than acknowledging
  it repeatedly.
- Never treat an absent state as false. `is_set` in `alarm_view.cpp` is the whole of that lesson:
  a condition that has not reported its active state is not an inactive condition.

## Related

- `examples/server/alarms` — the server that raises this alarm.
- `examples/client/events` — plain event monitoring, with no state to track.
- `examples/client/subscriptions` — watching a value change, rather than being told something is wrong.

//! The DIDComm protocols the mediator answers: Trust Ping 2.0, Discover Features
//! 2.0 and Report Problem 2.0.

use almena_didcomm::Message;
use serde_json::{Value, json};

use crate::push::Service;

pub const PING: &str = "https://didcomm.org/trust-ping/2.0/ping";
pub const PING_RESPONSE: &str = "https://didcomm.org/trust-ping/2.0/ping-response";
pub const QUERIES: &str = "https://didcomm.org/discover-features/2.0/queries";
pub const DISCLOSE: &str = "https://didcomm.org/discover-features/2.0/disclose";
pub const PROBLEM_REPORT: &str = "https://didcomm.org/report-problem/2.0/problem-report";

pub const COORDINATE_MEDIATION: &str = "https://didcomm.org/coordinate-mediation/3.0/";
pub const MEDIATE_REQUEST: &str = "https://didcomm.org/coordinate-mediation/3.0/mediate-request";
pub const MEDIATE_GRANT: &str = "https://didcomm.org/coordinate-mediation/3.0/mediate-grant";
pub const RECIPIENT_UPDATE: &str = "https://didcomm.org/coordinate-mediation/3.0/recipient-update";
pub const RECIPIENT_UPDATE_RESPONSE: &str =
    "https://didcomm.org/coordinate-mediation/3.0/recipient-update-response";
pub const RECIPIENT_QUERY: &str = "https://didcomm.org/coordinate-mediation/3.0/recipient-query";
pub const RECIPIENT: &str = "https://didcomm.org/coordinate-mediation/3.0/recipient";

pub const PICKUP: &str = "https://didcomm.org/messagepickup/3.0/";
pub const STATUS_REQUEST: &str = "https://didcomm.org/messagepickup/3.0/status-request";
pub const STATUS: &str = "https://didcomm.org/messagepickup/3.0/status";
pub const DELIVERY_REQUEST: &str = "https://didcomm.org/messagepickup/3.0/delivery-request";
pub const DELIVERY: &str = "https://didcomm.org/messagepickup/3.0/delivery";
pub const MESSAGES_RECEIVED: &str = "https://didcomm.org/messagepickup/3.0/messages-received";
pub const LIVE_DELIVERY_CHANGE: &str = "https://didcomm.org/messagepickup/3.0/live-delivery-change";

pub const PUSH_FCM: &str = "https://didcomm.org/push-notifications-fcm/1.0/";
pub const PUSH_APNS: &str = "https://didcomm.org/push-notifications-apns/1.0/";
/// Message names shared by both push protocols.
pub const SET_DEVICE_INFO: &str = "set-device-info";
pub const GET_DEVICE_INFO: &str = "get-device-info";
pub const DEVICE_INFO: &str = "device-info";
/// The `ack` of Aries RFC 0015, which the push protocols answer
/// `set-device-info` with.
pub const ACK: &str = "https://didcomm.org/notification/1.0/ack";

/// TURN credentials, an Almena protocol (SPEC.md §6.9).
pub const TURN: &str = "https://almena.id/protocols/turn/1.0/";
pub const TURN_CREDENTIALS_REQUEST: &str =
    "https://almena.id/protocols/turn/1.0/credentials-request";
pub const TURN_CREDENTIALS: &str = "https://almena.id/protocols/turn/1.0/credentials";

/// The push protocol of `service`, with the trailing `/` of a message type.
pub fn push_protocol(service: Service) -> &'static str {
    match service {
        Service::Fcm => PUSH_FCM,
        Service::Apns => PUSH_APNS,
    }
}

/// Feature of the mediator, as disclosed by Discover Features.
struct Feature {
    feature_type: &'static str,
    id: &'static str,
    roles: &'static [&'static str],
}

const FEATURES: &[Feature] = &[
    Feature {
        feature_type: "protocol",
        id: "https://didcomm.org/trust-ping/2.0",
        roles: &["receiver"],
    },
    Feature {
        feature_type: "protocol",
        id: "https://didcomm.org/discover-features/2.0",
        roles: &["responder"],
    },
    Feature {
        feature_type: "protocol",
        id: "https://didcomm.org/report-problem/2.0",
        roles: &[],
    },
    Feature {
        feature_type: "protocol",
        id: "https://didcomm.org/coordinate-mediation/3.0",
        roles: &["mediator"],
    },
    Feature {
        feature_type: "protocol",
        id: "https://didcomm.org/routing/2.0",
        roles: &["mediator"],
    },
    Feature {
        feature_type: "protocol",
        id: "https://didcomm.org/messagepickup/3.0",
        roles: &["mediator"],
    },
    Feature {
        feature_type: "header",
        id: "return_route",
        roles: &[],
    },
];

/// Trust Ping: a `ping-response` unless the sender asked for none.
pub fn trust_ping(ping: &Message) -> Option<Message> {
    let wanted = ping
        .body
        .get("response_requested")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    wanted.then(|| Message::new(PING_RESPONSE, json!({})).reply_to(ping))
}

/// Discover Features: a `disclose` listing the features that match any query,
/// including the push protocols of the services in `push` and the TURN
/// protocol when `turn` is on. Unknown feature types match nothing, as the
/// protocol requires.
pub fn discover_features(
    request: &Message,
    max_receive_bytes: usize,
    push: &[Service],
    turn: bool,
) -> Result<Message, Problem> {
    let queries = request
        .body
        .get("queries")
        .and_then(Value::as_array)
        .ok_or(Problem::InvalidBody)?;

    let mut disclosures = Vec::new();
    for query in queries {
        let (Some(feature_type), Some(pattern)) = (
            query.get("feature-type").and_then(Value::as_str),
            query.get("match").and_then(Value::as_str),
        ) else {
            return Err(Problem::InvalidBody);
        };
        for feature in FEATURES
            .iter()
            .filter(|f| f.feature_type == feature_type && matches(pattern, f.id))
        {
            let mut disclosure = json!({"feature-type": feature.feature_type, "id": feature.id});
            if !feature.roles.is_empty() {
                disclosure["roles"] = json!(feature.roles);
            }
            disclosures.push(disclosure);
        }
        if feature_type == "protocol" {
            for service in push {
                let id = push_protocol(*service).trim_end_matches('/');
                if matches(pattern, id) {
                    disclosures.push(json!({
                        "feature-type": "protocol",
                        "id": id,
                        "roles": ["notification-sender"],
                    }));
                }
            }
            let id = TURN.trim_end_matches('/');
            if turn && matches(pattern, id) {
                disclosures.push(json!({
                    "feature-type": "protocol",
                    "id": id,
                    "roles": ["server"],
                }));
            }
        }
        if feature_type == "constraint" && matches(pattern, "max_receive_bytes") {
            disclosures.push(json!({
                "feature-type": "constraint",
                "id": "max_receive_bytes",
                "max_receive_bytes": max_receive_bytes.to_string(),
            }));
        }
    }
    Ok(Message::new(DISCLOSE, json!({ "disclosures": disclosures })).reply_to(request))
}

/// `*` matches any run of characters; everything else matches literally.
fn matches(pattern: &str, value: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == value,
        Some((prefix, rest)) => {
            let Some(tail) = value.strip_prefix(prefix) else {
                return false;
            };
            (0..=tail.len())
                .filter(|&i| tail.is_char_boundary(i))
                .any(|i| matches(rest, &tail[i..]))
        }
    }
}

/// Problems the mediator reports back to the sender.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    /// The message type is not one the mediator handles.
    UnsupportedType,
    /// The body does not have the shape the message type requires.
    InvalidBody,
    /// `expires_time` has passed.
    Expired,
    /// Mediation, pickup, push and TURN messages need an authcrypted sender.
    Unauthenticated,
    /// The sender has no mediation with this mediator.
    NoMediation,
    /// A `recipient_did` that the sender's mediation has not registered.
    UnknownRecipient(String),
    /// `live_delivery: true` on a connection that cannot deliver live.
    LiveModeNotSupported,
}

impl Problem {
    fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedType => "e.m.msg.unsupported-type",
            Self::InvalidBody => "e.m.msg.invalid-body",
            Self::Expired => "e.m.req.time.expired",
            Self::Unauthenticated => "e.m.trust.unauthenticated",
            Self::NoMediation => "e.m.req.no-mediation",
            Self::UnknownRecipient(_) => "e.m.msg.unknown-recipient",
            // As Message Pickup 3.0 names it.
            Self::LiveModeNotSupported => "e.m.live-mode-not-supported",
        }
    }

    /// Static per code, as the spec requires of `comment`.
    fn comment(&self) -> &'static str {
        match self {
            Self::UnsupportedType => "Message type {1} is not supported.",
            Self::InvalidBody => "The message body is not valid for its type.",
            Self::Expired => "The message expired before it was processed.",
            Self::Unauthenticated => "This message must be authcrypted by its sender.",
            Self::NoMediation => "Request mediation first.",
            Self::UnknownRecipient(_) => "Recipient DID {1} is not registered by this mediation.",
            Self::LiveModeNotSupported => "Connection does not support Live Delivery",
        }
    }

    /// A problem report about `trigger`: a child thread of the trigger's
    /// thread that acknowledges the trigger.
    pub fn report(&self, trigger: &Message) -> Message {
        let mut body = json!({"code": self.code(), "comment": self.comment()});
        match self {
            Self::UnsupportedType => body["args"] = json!([trigger.type_]),
            Self::UnknownRecipient(did) => body["args"] = json!([did]),
            _ => {}
        }
        let mut report = Message::new(PROBLEM_REPORT, body).header("ack", json!([trigger.id]));
        report.pthid = Some(trigger.thid().to_owned());
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards() {
        assert!(matches("*", "anything"));
        assert!(matches(
            "https://didcomm.org/trust-ping/2.*",
            "https://didcomm.org/trust-ping/2.0"
        ));
        assert!(matches(
            "https://didcomm.org/*/2.0",
            "https://didcomm.org/trust-ping/2.0"
        ));
        assert!(!matches(
            "https://didcomm.org/trust-ping/1.*",
            "https://didcomm.org/trust-ping/2.0"
        ));
        assert!(matches("return_route", "return_route"));
        assert!(!matches("return", "return_route"));
    }

    #[test]
    fn ping_gets_a_response_in_its_thread() {
        let ping = Message::new(PING, json!({"response_requested": true}));
        let response = trust_ping(&ping).unwrap();
        assert_eq!(response.type_, PING_RESPONSE);
        assert_eq!(response.thid.as_deref(), Some(ping.id.as_str()));
    }

    #[test]
    fn ping_without_response_requested_gets_none() {
        assert!(trust_ping(&Message::new(PING, json!({"response_requested": false}))).is_none());
    }

    #[test]
    fn discover_features_discloses_matches_only() {
        let queries = Message::new(
            QUERIES,
            json!({"queries": [
                {"feature-type": "protocol", "match": "https://didcomm.org/trust-ping/*"},
                {"feature-type": "constraint", "match": "max_receive_bytes"},
                {"feature-type": "goal-code", "match": "*"},
                {"feature-type": "unknown", "match": "*"}
            ]}),
        );
        let disclose = discover_features(&queries, 65536, &[], false).unwrap();
        assert_eq!(disclose.thid.as_deref(), Some(queries.id.as_str()));
        let disclosures = disclose.body["disclosures"].as_array().unwrap();
        assert_eq!(disclosures.len(), 2);
        assert_eq!(disclosures[0]["id"], "https://didcomm.org/trust-ping/2.0");
        assert_eq!(disclosures[1]["max_receive_bytes"], "65536");
    }

    #[test]
    fn discover_features_rejects_a_bad_body() {
        let queries = Message::new(QUERIES, json!({"queries": "all"}));
        assert_eq!(
            discover_features(&queries, 1, &[], false).unwrap_err(),
            Problem::InvalidBody
        );
    }

    #[test]
    fn problem_report_points_at_the_trigger() {
        let trigger = Message::new("https://example.com/x/1.0/y", json!({}));
        let report = Problem::UnsupportedType.report(&trigger);
        assert_eq!(report.pthid.as_deref(), Some(trigger.id.as_str()));
        assert_eq!(report.extra_headers["ack"], json!([trigger.id]));
        assert_eq!(report.body["args"], json!([trigger.type_]));
    }
}

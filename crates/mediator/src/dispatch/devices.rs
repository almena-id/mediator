//! The push protocols, mediator side: Aries RFC 0734 (FCM) and RFC 0699
//! (APNs), carried in DIDComm v2 messages with their bodies unchanged. A
//! wallet registers the device its mediation wakes; `set-device-info` is
//! answered with an RFC 0015 `ack`, all-`null` values remove the device.
//!
//! The APNs messages also carry Almena's `voip_device_token`: the PushKit
//! token calls ring (SPEC.md §6.3). It is part of the same registration, so
//! a `set-device-info` without it removes the VoIP token the device had:
//! one message always describes the whole device.

use serde_json::{Value, json};

use almena_didcomm::Message;

use super::protocols::{
    self, ACK, DEVICE_INFO, GET_DEVICE_INFO, Problem, SET_DEVICE_INFO, push_protocol,
};
use super::{Handled, Mediator};
use crate::push::{Device, Service};

/// Longest FCM token accepted (they are about 160 characters today).
const MAX_FCM_TOKEN: usize = 4096;
/// Longest APNs token accepted (64 hex digits today), alert or VoIP.
const MAX_APNS_TOKEN: usize = 200;
/// Almena's field for the PushKit token in the APNs messages.
const VOIP_DEVICE_TOKEN: &str = "voip_device_token";
const MAX_PLATFORM: usize = 64;

/// Handles a push protocol message from `requester` (an authenticated DID).
pub async fn handle(
    mediator: &Mediator,
    requester: &str,
    message: &Message,
) -> anyhow::Result<Handled> {
    let t = message.type_.as_str();
    let (service, name) = if let Some(name) = t.strip_prefix(protocols::PUSH_FCM) {
        (Service::Fcm, name)
    } else if let Some(name) = t.strip_prefix(protocols::PUSH_APNS) {
        (Service::Apns, name)
    } else {
        return Ok(Handled::Problem(Problem::UnsupportedType));
    };
    // Only the services this mediator can push through.
    if !mediator
        .pusher()
        .is_some_and(|pusher| pusher.services().contains(&service))
    {
        return Ok(Handled::Problem(Problem::UnsupportedType));
    }
    let store = mediator.store();
    if !store.has_mediation(requester).await? {
        return Ok(Handled::Problem(Problem::NoMediation));
    }

    match name {
        SET_DEVICE_INFO => {
            let Some(devices) = parse_devices(service, &message.body) else {
                return Ok(Handled::Problem(Problem::InvalidBody));
            };
            for (service, device) in devices {
                store
                    .set_device(requester, service, device.as_ref())
                    .await?;
                tracing::debug!(mediation = %requester, service = service.as_str(), registered = device.is_some(), "device info set");
            }
            Ok(Handled::Reply(
                Message::new(ACK, json!({"status": "OK"})).reply_to(message),
            ))
        }
        GET_DEVICE_INFO => {
            let devices = store.devices(requester).await?;
            let device = |wanted: Service| {
                devices
                    .iter()
                    .find_map(|(s, device)| (*s == wanted).then_some(device))
            };
            let mut body = json!({"device_token": device(service).map(|d| &d.token)});
            match service {
                Service::Fcm => {
                    body["device_platform"] =
                        json!(device(service).and_then(|d| d.platform.as_deref()));
                }
                Service::Apns | Service::ApnsVoip => {
                    body[VOIP_DEVICE_TOKEN] = json!(device(Service::ApnsVoip).map(|d| &d.token));
                }
            }
            let info = Message::new(format!("{}{DEVICE_INFO}", push_protocol(service)), body);
            Ok(Handled::Reply(info.reply_to(message)))
        }
        _ => Ok(Handled::Problem(Problem::UnsupportedType)),
    }
}

/// The devices a `set-device-info` body registers, by service: `None` for a
/// service removes its device; `None` overall means the body is not valid.
/// An APNs body sets both the alert and the VoIP token.
fn parse_devices(service: Service, body: &Value) -> Option<Vec<(Service, Option<Device>)>> {
    // A missing field counts as `null`.
    let field = |name: &str| match body.get(name) {
        None | Some(Value::Null) => Some(None),
        Some(Value::String(value)) => Some(Some(value.as_str())),
        Some(_) => None,
    };
    let apns = |token: Option<&str>| match token {
        None => Some(None),
        Some(token) if is_apns_token(token) => Some(Some(Device {
            token: token.to_owned(),
            platform: None,
        })),
        Some(_) => None,
    };
    let token = field("device_token")?;
    match service {
        Service::Apns | Service::ApnsVoip => Some(vec![
            (Service::Apns, apns(token)?),
            (Service::ApnsVoip, apns(field(VOIP_DEVICE_TOKEN)?)?),
        ]),
        Service::Fcm => match (token, field("device_platform")?) {
            (None, None) => Some(vec![(Service::Fcm, None)]),
            (Some(token), Some(platform))
                if is_fcm_token(token)
                    && !platform.is_empty()
                    && platform.len() <= MAX_PLATFORM =>
            {
                Some(vec![(
                    Service::Fcm,
                    Some(Device {
                        token: token.to_owned(),
                        platform: Some(platform.to_owned()),
                    }),
                )])
            }
            // Only one of the two is `null`: the RFC allows a problem report.
            _ => None,
        },
    }
}

fn is_fcm_token(token: &str) -> bool {
    !token.is_empty() && token.len() <= MAX_FCM_TOKEN && token.bytes().all(|b| b.is_ascii_graphic())
}

/// Hex only: the token goes into the APNs request path.
fn is_apns_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_APNS_TOKEN
        && token.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_bodies() {
        let fcm = |body| parse_devices(Service::Fcm, &body);
        let apns = |body| parse_devices(Service::Apns, &body);
        let device = |token: &str, platform: Option<&str>| Device {
            token: token.into(),
            platform: platform.map(Into::into),
        };
        assert_eq!(
            fcm(json!({"device_token": "tok:en", "device_platform": "android"})),
            Some(vec![(
                Service::Fcm,
                Some(device("tok:en", Some("android")))
            )])
        );
        assert_eq!(
            fcm(json!({"device_token": null, "device_platform": null})),
            Some(vec![(Service::Fcm, None)])
        );
        assert_eq!(fcm(json!({})), Some(vec![(Service::Fcm, None)]));
        assert_eq!(
            fcm(json!({"device_token": "t", "device_platform": null})),
            None
        );
        assert_eq!(
            fcm(json!({"device_token": "a b", "device_platform": "ios"})),
            None
        );
        assert_eq!(
            fcm(json!({"device_token": 7, "device_platform": "ios"})),
            None
        );

        // Without a VoIP token, the device has none.
        assert_eq!(
            apns(json!({"device_token": "a1B2"})),
            Some(vec![
                (Service::Apns, Some(device("a1B2", None))),
                (Service::ApnsVoip, None)
            ])
        );
        assert_eq!(
            apns(json!({"device_token": "a1B2", "voip_device_token": "c3d4"})),
            Some(vec![
                (Service::Apns, Some(device("a1B2", None))),
                (Service::ApnsVoip, Some(device("c3d4", None)))
            ])
        );
        assert_eq!(
            apns(json!({"device_token": null, "voip_device_token": null})),
            Some(vec![(Service::Apns, None), (Service::ApnsVoip, None)])
        );
        assert_eq!(apns(json!({"device_token": "../3/device/x"})), None);
        assert_eq!(apns(json!({"device_token": ""})), None);
        assert_eq!(
            apns(json!({"device_token": "a1", "voip_device_token": "not hex"})),
            None
        );
        assert_eq!(
            apns(json!({"device_token": "a1", "voip_device_token": "f".repeat(201)})),
            None
        );
        assert_eq!(
            apns(json!({"device_token": "a1", "voip_device_token": 7})),
            None
        );
    }
}

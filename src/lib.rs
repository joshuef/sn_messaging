// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

pub mod client;
mod errors;
pub mod location;
mod msg_id;
#[cfg(not(feature = "client-only"))]
pub mod node;
pub mod section_info;
mod serialisation;

pub use self::{
    errors::{Error, Result},
    location::{DstLocation, EndUser, SrcLocation},
    msg_id::MessageId,
    serialisation::WireMsg,
};
use bytes::Bytes;
use sn_data_types::PublicKey;

type DestinationKey = PublicKey;

/// Type of message.
/// Note this is part of this crate's public API but this enum is
/// never serialised or even part of the message that is sent over the wire.
#[derive(PartialEq, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum MessageType {
    Ping,
    SectionInfo((section_info::Message, DestinationKey)),
    ClientMessage((client::Message, DestinationKey)),
    #[cfg(not(feature = "client-only"))]
    NodeMessage((node::NodeMessage, DestinationKey)),
}

impl MessageType {
    /// serialize the message type into bytes ready to be sent over the wire.
    pub fn serialize(&self) -> Result<Bytes> {
        match self {
            Self::Ping => WireMsg::new_ping_msg().serialize(),
            Self::SectionInfo((query, dest_pk)) => {
                WireMsg::serialize_sectioninfo_msg(query, *dest_pk)
            }
            Self::ClientMessage((msg, dest_pk)) => WireMsg::serialize_client_msg(msg, *dest_pk),
            #[cfg(not(feature = "client-only"))]
            Self::NodeMessage((msg, dest_pk)) => WireMsg::serialize_node_msg(msg, *dest_pk),
        }
    }
}

// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{Error, MessageType, Result, WireMsg};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sn_data_types::PublicKey;
use std::fmt::{self, Debug, Formatter};

/// Node message sent over the network.
// TODO: this is currently holding just bytes as a placeholder, next step
// is to move all actual node messages structs and definitions within it.
#[derive(Clone, Eq, Serialize, Deserialize)]
pub struct NodeMessage(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl NodeMessage {
    /// Creates a new instance which wraps the provided node message bytes.
    pub fn new(bytes: Bytes) -> Self {
        Self(bytes.to_vec())
    }

    /// Convenience function to deserialize a 'NodeMessage' from bytes received over the wire.
    /// It returns an error if the bytes don't correspond to a node message.
    pub fn from(bytes: Bytes) -> Result<Self> {
        let deserialized = WireMsg::deserialize(bytes)?;
        if let MessageType::NodeMessage((msg, _dest_pk)) = deserialized {
            Ok(msg)
        } else {
            Err(Error::FailedToParse("bytes as a node message".to_string()))
        }
    }

    /// Return the destination section PublicKey for this message
    pub fn dest_pk(bytes: Bytes) -> crate::Result<PublicKey> {
        let deserialized = WireMsg::deserialize(bytes)?;
        if let MessageType::NodeMessage((_query, dest_pk)) = deserialized {
            Ok(dest_pk)
        } else {
            Err(crate::Error::FailedToParse(
                "bytes as a node message".to_string(),
            ))
        }
    }

    /// serialize this NodeMessage into bytes ready to be sent over the wire.
    pub fn serialize(&self, dest_pk: PublicKey) -> Result<Bytes> {
        WireMsg::serialize_node_msg(self, dest_pk)
    }
}

impl PartialEq for NodeMessage {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Debug for NodeMessage {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter
            .debug_tuple("NodeMessage")
            .field(&format_args!("{:10}", hex_fmt::HexFmt(&self.0)))
            .finish()
    }
}

// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

mod wire_msg_header;

use self::wire_msg_header::{MessageKind, WireMsgHeader};
#[cfg(not(feature = "client-only"))]
use super::node;
use super::{client, section_info, Error, MessageType, Result};
use bytes::Bytes;
use cookie_factory::{combinator::slice, gen};
use sn_data_types::PublicKey;
use std::fmt::Debug;

// In order to send a message over the wire, it needs to be serialized
// along with a header (WireMsgHeader) which contains the information needed
// by the recipient to properly deserialize it.
// The WireMsg struct provides the utilities to serialize and deserialize messages.
#[derive(Debug, PartialEq)]
pub struct WireMsg {
    header: WireMsgHeader,
    payload: Bytes,
}

impl WireMsg {
    /// Creates a new instance of a 'Ping' message.
    pub fn new_ping_msg() -> WireMsg {
        Self {
            header: WireMsgHeader::new(MessageKind::Ping),
            payload: Bytes::new(),
        }
    }

    /// Creates a new instance keeping a (serialized) copy of the 'SectionInfo' message provided.
    pub fn new_sectioninfo_msg(
        query: &section_info::Message,
        dest_key: PublicKey,
    ) -> Result<WireMsg> {
        let payload_vec = rmp_serde::to_vec_named(&(query, dest_key)).map_err(|err| {
            Error::Serialisation(format!(
                "could not serialize network info payload with Msgpack: {}",
                err
            ))
        })?;

        Ok(Self {
            header: WireMsgHeader::new(MessageKind::SectionInfo),
            payload: Bytes::from(payload_vec),
        })
    }

    /// Creates a new instance keeping a (serialized) copy of the client 'Message' message provided.
    pub fn new_client_msg(msg: &client::Message, dest_key: PublicKey) -> Result<WireMsg> {
        let payload_vec = rmp_serde::to_vec_named(&(msg, dest_key)).map_err(|err| {
            Error::Serialisation(format!(
                "could not serialize client message payload (id: {}) with Msgpack: {}",
                msg.id(),
                err
            ))
        })?;

        Ok(Self {
            header: WireMsgHeader::new(MessageKind::ClientMessage),
            payload: Bytes::from(payload_vec),
        })
    }

    /// Creates a new instance keeping a (serialized) copy of the node 'Message' message provided.
    #[cfg(not(feature = "client-only"))]
    pub fn new_node_msg(msg: &node::NodeMessage, dest_key: PublicKey) -> Result<WireMsg> {
        let payload_vec = rmp_serde::to_vec_named(&(msg, dest_key)).map_err(|err| {
            Error::Serialisation(format!(
                "could not serialize node message payload with Msgpack: {}",
                err
            ))
        })?;

        Ok(Self {
            header: WireMsgHeader::new(MessageKind::NodeMessage),
            payload: Bytes::from(payload_vec),
        })
    }

    /// Attempts to create an instance of WireMsg by deserialising the bytes provided.
    /// To succeed, the bytes should contain at least a valid WireMsgHeader.
    pub fn from(bytes: Bytes) -> Result<Self> {
        // Deserialize the header bytes first
        let (header, payload) = WireMsgHeader::from(bytes)?;
        // We can now create a deserialized WireMsg using the read bytes
        Ok(Self { header, payload })
    }

    // /// Return the destination section PublicKey for this message
    // pub fn dest_pk(&self) -> Result<PublicKey> {
    //     let deserialized = WireMsg::deserialize(self.payload.clone())?;

    //     match deserialized {
    //         MessageType::ClientMessage((_, dest_pk)) | MessageType::SectionInfo((_, dest_pk)) => {
    //             Ok(dest_pk)
    //         },
    //         #[cfg(not(feature = "client-only"))]
    //         MessageType::NodeMessage((_, dest_pk)) => Ok(dest_pk),
    //         _ => {

    //             Err(crate::Error::FailedToParse(
    //                 "dest key from message. It does not have a dest key".to_string(),
    //             ))
    //         }
    //     }

    // }

    /// Return the serialized WireMsg, which contains the WireMsgHeader bytes,
    /// followed by the payload bytes, i.e. the serialized Message.
    pub fn serialize(&self) -> Result<Bytes> {
        // First we create a buffer with the exact size
        // needed to serialize the wire msg
        let mut buffer = vec![0u8; self.size()];

        let buf_at_payload = self.header.write(&mut buffer)?;

        // ...and finally we write the bytes of the serialized payload
        let _ = gen(slice(self.payload.clone()), &mut buf_at_payload[..]).map_err(|err| {
            Error::Serialisation(format!("message payload couldn't be serialized: {}", err))
        })?;

        // We can now return the buffer containing the written bytes
        Ok(Bytes::from(buffer))
    }

    /// Deserialize the payload from this WireMsg returning a Message instance.
    pub fn to_message(&self) -> Result<MessageType> {
        match self.header.kind() {
            MessageKind::Ping => Ok(MessageType::Ping),
            MessageKind::SectionInfo => {
                let msg_contents: (section_info::Message, PublicKey) =
                    rmp_serde::from_slice(&self.payload).map_err(|err| {
                        Error::FailedToParse(format!(
                            "Client message payload as Msgpack: {}",
                            err
                        ))
                    })?;
                Ok(MessageType::SectionInfo(msg_contents))
            }
            MessageKind::ClientMessage => {
                let client_msg: (client::Message, PublicKey) =
                    rmp_serde::from_slice(&self.payload).map_err(|err| {
                        Error::FailedToParse(format!(
                            "Client message payload as Msgpack: {}",
                            err
                        ))
                    })?;
                Ok(MessageType::ClientMessage(client_msg))
            }
            #[cfg(feature = "client-only")]
            MessageKind::NodeMessage => {
                Err(Error::FailedToParse("Message payload is a Node message which is not supported when feature 'client-only' is set".to_string()))
            }
            #[cfg(not(feature = "client-only"))]
            MessageKind::NodeMessage => {
                let node_msg: (node::NodeMessage, PublicKey) =
                    rmp_serde::from_slice(&self.payload).map_err(|err| {
                        Error::FailedToParse(format!("Node message payload as Msgpack: {}", err))
                    })?;
                Ok(MessageType::NodeMessage(node_msg))
            }
        }
    }

    // The following functions are just for convenience, which allow users to
    // not needing to create an instance of WireMsg beforehand.

    /// Convenience function which creates a temporary WireMsg from the provided
    /// bytes, returning the deserialized message.
    pub fn deserialize(bytes: Bytes) -> Result<MessageType> {
        let i = Self::from(bytes)?;
        i.to_message()
    }

    /// Convenience function which creates a temporary WireMsg from the provided
    /// MsgEnvelope, returning the serialized WireMsg.
    pub fn serialize_sectioninfo_msg(
        query: &section_info::Message,
        dest_key: PublicKey,
    ) -> Result<Bytes> {
        Self::new_sectioninfo_msg(query, dest_key)?.serialize()
    }

    /// Convenience function which creates a temporary WireMsg from the provided
    /// Message, returning the serialized WireMsg.
    pub fn serialize_client_msg(msg: &client::Message, dest_key: PublicKey) -> Result<Bytes> {
        Self::new_client_msg(msg, dest_key)?.serialize()
    }

    /// Convenience function which creates a temporary WireMsg from the provided
    /// node::Messsage, returning the serialized WireMsg.
    #[cfg(not(feature = "client-only"))]
    pub fn serialize_node_msg(msg: &node::NodeMessage, dest_key: PublicKey) -> Result<Bytes> {
        Self::new_node_msg(msg, dest_key)?.serialize()
    }

    // Private function which returns the bytes size of this WireMsg
    // taking into account current self-contained payload.
    fn size(&self) -> usize {
        WireMsgHeader::size() + self.payload.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use rand_core::OsRng;
    use sn_data_types::Keypair;
    use xor_name::XorName;

    #[test]
    fn serialisation_ping() -> Result<()> {
        let wire_msg = WireMsg::new_ping_msg();
        let serialized = wire_msg.serialize()?;
        let deserialized = WireMsg::from(serialized)?;
        assert_eq!(deserialized, wire_msg);
        assert_eq!(wire_msg.to_message()?, MessageType::Ping);

        Ok(())
    }

    #[test]
    fn serialisation_sectioninfo_msg() -> Result<()> {
        let random_xor = XorName::random();
        let mut rng = OsRng;
        let section_pk = Keypair::new_ed25519(&mut rng).public_key();
        let query = section_info::Message::GetSectionQuery(random_xor);
        let wire_msg = WireMsg::new_sectioninfo_msg(&query, section_pk)?;
        let serialized = wire_msg.serialize()?;
        let deserialized = WireMsg::from(serialized)?;
        assert_eq!(deserialized, wire_msg);
        assert_eq!(
            wire_msg.to_message()?,
            MessageType::SectionInfo((query, section_pk))
        );

        // assert_eq!(wire_msg.dest_pk()?, section_pk);

        Ok(())
    }
}

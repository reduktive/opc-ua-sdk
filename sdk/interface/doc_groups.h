// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DOC_GROUPS_H
#define UA_DOC_GROUPS_H

/// @file
/// @brief Doxygen module-group registry for the public API reference.
///
/// This header contains no code. It defines the canonical `@defgroup` set that
/// public types join via `@ingroup`.

/// @defgroup core_types Core types
/// @brief Hand-written built-in OPC UA types: NodeId, Variant, StatusCode,
/// DataValue, QualifiedName, LocalizedText, and friends. The generated NS0
/// data types and identifiers live in their own modules (see below).

/// @defgroup security Security
/// @brief Cryptography, certificates, security policies, and the certificate
/// store (client and server).

/// @defgroup address_space Address space
/// @brief The node/reference graph model, instantiation engine, conditions,
/// and NodeSet helpers.

/// @defgroup client Client
/// @brief Client-side API: sessions, subscriptions, and service calls.

/// @defgroup server Server
/// @brief Server entry point, endpoint configuration, services, and
/// authentication/authorization hooks.

/// @defgroup transport Transport
/// @brief TCP transport: connections, acceptors, connectors, and protocol
/// framing.

/// @defgroup async Async
/// @brief Strand, on-strand helper, trampoline, timer, and registry
/// utilities.

/// @defgroup codecs Codecs
/// @brief UA Binary and XML encoders/decoders.

/// @defgroup streams Streams
/// @brief Stream and memory-buffer abstractions used by the codecs.

/// @defgroup general General
/// @brief Shared utilities: results, error detail, logging, and helpers.

/// @defgroup app Application
/// @brief Application-description and bootstrap types shared by client and
/// server.

/// @defgroup history Historical Access
/// @brief Historical Access: the engine that answers HistoryRead and HistoryUpdate, the store
/// interface behind it, the SQLite store that implements one, and the annotations property.

/// @defgroup ua_data_types OPC UA Data Types
/// @brief Generated OPC UA data types - structures, enumerations, option sets,
/// and unions from the standard namespace-0 information model (service request
/// and response messages, attribute structures, filters, and so on).

/// @defgroup ua_node_ids OPC UA Identifiers
/// @brief Generated well-known numeric identifiers (DataTypeId, ObjectId,
/// ReferenceTypeId, VariableId, ...) and the symbolic StatusCode constants for
/// the standard namespace 0.

/// @defgroup ua_information_model OPC UA Information Model
/// @brief Generated address-space handles for the standard ObjectTypes,
/// VariableTypes, and event-type payloads - the typed instance helpers used to
/// create and access nodes.

#endif  // UA_DOC_GROUPS_H

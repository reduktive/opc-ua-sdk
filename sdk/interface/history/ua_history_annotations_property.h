// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_HISTORY_ANNOTATIONS_PROPERTY_H
#define UA_HISTORY_ANNOTATIONS_PROPERTY_H

#include "ua_namespace_history_delegate.h"
#include "ua_instantiation_options.h"
#include "ua_node_id.h"
#include "ua_property.h"

namespace ua
{
class AddressSpace;
}

namespace ua::history
{

/// @ingroup history
/// Adds the OPC 10000-11 section 5.1 Annotations Property to a HistoricalDataNode.
///
/// The Annotations Property (BrowseName "Annotations" in ns=0, DataType `Annotation`, a
/// `PropertyType` reached via `HasProperty`) marks `node` as a node whose history collection supports
/// Annotation data (Part 11 section 5.1, Table 2). Its *presence* is the contract clients rely on; the
/// Annotation data itself is read via HistoryRead (`ReadAnnotationDataDetails`) and modified via
/// HistoryUpdate (`UpdateStructuredDataDetails`), not through this Property's Value. The Value is
/// seeded with a default marker `Annotation` so a plain Read returns a well-formed value.
///
/// Per Part 11 section 5.1 (SVR-HIST-ANN-009) the property is added **only** when `delegate` actually
/// supports Annotations  -  i.e. it advertises `read_annotations` or `insert_annotation`. When it does
/// not, no node is created and a `Bad_NotSupported` error is returned so callers can detect a
/// misconfiguration rather than silently advertising an unsupported capability.
///
/// The created node is released from the returned handle's RAII subtree so it persists for the
/// lifetime of the address space (the handle is a non-owning view on return).
///
/// @param addressSpace Address space the node lives in.
/// @param node         The HistoricalDataNode to attach the Annotations Property to.
/// @param delegate     History delegate whose capabilities gate the add.
/// @param options      Instantiation options (node-id allocation, target namespace, ...). The first
///                     (only) node allocated is the Annotations Property itself.
/// @return The `Property` handle on success, or an `ErrorDetail`-bearing error result. Never throws.
ua::PropertyResult add_annotations_property(ua::AddressSpace addressSpace, const ua::NodeId& node,
  const ua::NamespaceHistoryDelegate& delegate, const ua::InstantiationOptions& options);

}  // namespace ua::history

#endif  // !UA_HISTORY_ANNOTATIONS_PROPERTY_H

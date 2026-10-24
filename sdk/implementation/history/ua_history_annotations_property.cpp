// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_history_annotations_property.h"

#include "ua_access_level_type.h"
#include "ua_address_space.h"
#include "ua_annotation.h"
#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_datatype_id.h"
#include "ua_error_detail.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_status_code.h"
#include "ua_string.h"
#include "ua_value_rank.h"
#include "ua_instantiation_options.h"
#include "ua_variant.h"

namespace ua::history
{

ua::PropertyResult add_annotations_property(ua::AddressSpace addressSpace, const ua::NodeId& node,
  const ua::NamespaceHistoryDelegate& delegate, const ua::InstantiationOptions& options)
{
  // SVR-HIST-ANN-009 (Part 11 section 5.1): only advertise the Annotations Property on a node whose history
  // collection actually supports Annotations (read or update). Otherwise the property is a false
  // contract  -  clients would offer annotation editing the server cannot honour.
  const auto caps = delegate.capabilities();
  if (!caps.readAnnotations && !caps.insertAnnotation)
  {
    return ua::PropertyResult{ua::StatusCode{ua::Status::BadNotSupported},
      ua::make_error_detail("AnnotationsNotSupported",
        "Annotations Property not added: the history delegate advertises neither read_annotations "
        "nor insert_annotation (Part 11 section 5.1 / SVR-HIST-ANN-009)",
        "ua::history::add_annotations_property")};
  }

  // Table 2: BrowseName "Annotations" (ns=0), DataType Annotation, a PropertyType. CurrentRead only  -
  // annotation data is mutated through HistoryUpdate (UpdateStructuredDataDetails), never by writing
  // this Property's Value.
  const ua::VariableInstantiationAttributes attributes{.dataType = ua::NodeId{ua::DataTypeId::Annotation},
    .valueRank = ua::ValueRank::scalar,
    .accessLevel = ua::AccessLevelType{ua::AccessLevelType::Bit::CurrentRead}};

  // A Property is reached from its owner via HasProperty (Part 3 section 5.9). Force it here so callers can
  // reuse their generic instantiation options (whose parentReferenceType is typically Organizes /
  // HasComponent) without the Annotations Property being mis-linked.
  auto propertyOptions = options;
  propertyOptions.parentReferenceType = ua::NodeId{ua::ReferenceTypeId::HasProperty};

  auto property = ua::Property::try_create_sync(
    addressSpace, node, ua::QualifiedName{0, "Annotations"}, propertyOptions, attributes);
  if (!property)
    return property;

  // The Property's presence  -  not its Value  -  is the spec contract (Part 11 section 5.1: "The presence of
  // the Annotations Property does not indicate the presence of Annotations"). Seed a default marker so
  // a direct Read of the Value attribute returns a well-formed Annotation pointing at the real access
  // path. The instantiation engine materialises the value cell; the internal write below bypasses
  // access control (it is not a service request).
  ua::Annotation marker;
  marker.message() = ua::String{"Annotation data is read via HistoryRead (ReadAnnotationDataDetails)"};
  marker.annotation_time() = ua::DateTime::now();
  ua::DataValue markerValue{ua::Variant{std::move(marker)}};
  markerValue.source_timestamp() = ua::DateTime::now();
  markerValue.server_timestamp() = ua::DateTime::now();
  property.value().write_value_sync(std::move(markerValue));

  // Release the owned subtree so the node persists for the lifetime of the address space; the returned
  // handle is then a non-owning view.
  property.value().release();
  return property;
}

}  // namespace ua::history

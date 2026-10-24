// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The extension point naming the OPC UA DataType of a C++ type.
/// @ingroup core_types

#ifndef UA_DATA_TYPE_TRAIT_H
#define UA_DATA_TYPE_TRAIT_H

namespace ua
{

/// Names the OPC UA DataType a C++ type describes, for @ref ua::data_type_of.
///
/// The primary template is empty: a type with no specialisation, no generated `typeId` and no array
/// or optional form of a mapped type has no DataType, and @ref ua::data_type_of refuses it at compile time.
/// The type generator specialises it for every enumeration it emits; ua_data_type_of.h specialises it
/// for the built-in types; an application may specialise it for a structure type it wrote by hand.
/// A specialisation declares two members:
///
/// @code
/// template<>
/// struct ua::DataTypeOf<MyRecipe>
/// {
///   static constexpr uint32_t id{3005};                                  // or an enumerator
///   static constexpr std::string_view namespaceUri{"urn:example:recipes"};  // the DataType's namespace
/// };
/// @endcode
///
/// @tparam T The C++ type.
/// @ingroup core_types
template<typename T>
struct DataTypeOf
{};

}  // namespace ua

#endif  // UA_DATA_TYPE_TRAIT_H

// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_BINARY_DATA_VALUE_CODEC_H
#define UA_BINARY_DATA_VALUE_CODEC_H

#include "ua_byte_string.h"
#include "ua_result.h"
#include "ua_structure_factory.h"

#include <memory>
#include <span>

/// @file
/// @brief Encoder/decoder for `DataValue` to and from the OPC UA Binary wire format.
/// @ingroup codecs

namespace ua
{

class DataValue;
struct CodecNamespaceContext;
struct EncodingLimits;

/// Outcome of a `UaBinaryDataValueCodec` decode: a `DataValue` or an `ErrorDetail`.
using DataValueResult = Result<DataValue>;

/// Encodes and decodes @ref DataValue instances to and from the OPC UA Binary wire format.
///
/// All state is fixed at construction, so a single instance is safe to share across threads
/// and use concurrently. Construct via @ref create; in server contexts an instance is normally
/// obtained from `Server::ua_binary_data_value_codec()`, which wires it to the server's
/// namespace table and structure registry.
///
/// Movable but not copyable; ownership is held through a `unique_ptr` returned by @ref create.
/// @ingroup codecs
class UaBinaryDataValueCodec
{
public:
  ~UaBinaryDataValueCodec();

  UaBinaryDataValueCodec(const UaBinaryDataValueCodec&) = delete;
  UaBinaryDataValueCodec& operator=(const UaBinaryDataValueCodec&) = delete;

  /// Move-constructs a codec, leaving the source in a valid but unspecified state.
  UaBinaryDataValueCodec(UaBinaryDataValueCodec&&) noexcept;

  /// Move-assigns a codec, leaving the source in a valid but unspecified state.
  /// @return Reference to this codec.
  UaBinaryDataValueCodec& operator=(UaBinaryDataValueCodec&&) noexcept;

  /// Encodes a @ref DataValue into its OPC UA Binary representation.
  ///
  /// @param value Value to serialise.
  /// @return The encoded bytes.
  /// @throws UaException if encoding cannot complete. The encoder is given only the nesting/work
  ///         budget from @ref EncodingLimits (`EncodingLimits::stack_depth()`), so a structure that
  ///         nests deeper than that budget fails; the size caps
  ///         (`mMaxStringLength` / `mMaxByteStringLength` / `mMaxArrayLength`) are **not** applied on
  ///         this path. The encoder's own size check is the wire ceiling: a String, ByteString or
  ///         array longer than `INT32_MAX` throws `BadInvalidArgument`, because the length prefix is
  ///         an `Int32`. An unencodable value - a NodeId identifier type the binary encoding has no
  ///         form for, or a Variant holding DiagnosticInfo - throws `BadEncodingError`.
  /// @note This is the throwing counterpart to @ref decode, which never throws and reports failure
  ///       through a @ref Result instead.
  /// @see decode
  ByteString encode(const DataValue& value) const;

  /// Decodes a @ref DataValue from its OPC UA Binary representation.
  ///
  /// All decode failures - including malformed or truncated @p data, arrays/strings that exceed the
  /// configured @ref EncodingLimits, and structures nested past the configured stack depth - are
  /// caught internally and surfaced through the returned @ref Result rather than thrown.
  ///
  /// @param data Encoded bytes to read; not retained beyond the call.
  /// @return The decoded @ref DataValue, or an @ref ErrorDetail describing why the input could not
  ///         be decoded. Never throws.
  /// @see encode
  DataValueResult decode(std::span<const byte> data) const;

  /// Creates a codec bound to the given structure resolver, namespace context, and limits.
  ///
  /// Server code normally calls `Server::ua_binary_data_value_codec()` instead of constructing
  /// a codec directly.
  ///
  /// @param structureResolver Resolves structured DataTypes encountered while (de)coding; moved
  ///                          into the codec.
  /// @param namespaceConfig   Namespace-table context applied to NodeIds and qualified names;
  ///                          moved into the codec.
  /// @param encodingLimits    Bounds applied asymmetrically. The size caps
  ///                          (`mMaxStringLength` / `mMaxByteStringLength` / `mMaxArrayLength`) are
  ///                          enforced on **decode only**, where they guard against malformed or
  ///                          hostile input; the encoder never consults them. Both directions
  ///                          receive the nesting/work budget (`stack_depth()`), which bounds how
  ///                          deeply a structure may nest.
  /// @return The owned codec instance.
  static std::unique_ptr<UaBinaryDataValueCodec> create(StructureResolver structureResolver,
    CodecNamespaceContext namespaceConfig, EncodingLimits encodingLimits);

private:
  explicit UaBinaryDataValueCodec(std::unique_ptr<class UaBinaryDataValueCodecImpl> impl);

  std::unique_ptr<UaBinaryDataValueCodecImpl> mImpl;
};

}  // namespace ua

#endif  // !UA_BINARY_DATA_VALUE_CODEC_H

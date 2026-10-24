// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

/// @file
/// @brief Listing, reading, and creating files on a server, through OPC UA.
///
/// It talks to `examples/server/file_transfer`, which must already be running. Start that first, in
/// another terminal, then run this.
///
/// A file arrives through the same Session as everything else, so it carries the same security and
/// the same authorization as a Read of a Variable. The SDK's `FileTransferClient` handles the
/// Open/Read/Close sequence; the `FileHandle` it returns closes the server-side handle when it goes
/// out of scope, so an abandoned transfer does not leak one.

#include "example_pki.h"
#include "example_support.h"

#include "ua_application_configuration.h"
#include "ua_client.h"
#include "ua_connection.h"
#include "ua_easy_connect_policy.h"
#include "ua_exceptions.h"
#include "ua_file_transfer_client.h"
#include "ua_hierarchical_path.h"
#include "ua_namespace_table.h"
#include "ua_object_id.h"
#include "ua_runtime.h"
#include "ua_typed_access.h"

#include <fmt/format.h>

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace std::chrono_literals;

namespace
{
// Change these for your server.
constexpr std::string_view defaultEndpointUrl = "opc.tcp://127.0.0.1:4846";
constexpr std::string_view namespaceUri = "urn:reduktive:opcua-sdk:example:files";
constexpr std::string_view directoryName = "Documents";
constexpr std::string_view seedFileName = "manual.txt";
constexpr std::string_view newFileName = "reading.txt";
constexpr std::string_view newFileContent = "Written over OPC UA.\n";
constexpr std::string_view subdirectoryName = "Manuals";
// A file is read in chunks the size the caller chooses; a real transfer sizes these against the
// server's advertised MaxByteStringLength rather than picking a number.
constexpr std::uint32_t chunkBytes = 16;
// How long to wait for endpoint discovery and the Session handshake to complete.
constexpr auto connectTimeout = 10s;

/// Creates the client and hands it to the Runtime to own.
ua::client::Client& create_client(ua::Runtime& runtime, const examples::DevelopmentPki& pki)
{
  auto application = ua::ApplicationConfig::load_default();
  application.application_description_part().applicationUri =
    std::string{examples::development_application_uri(examples::PkiRole::Client)};

  return runtime.attach(ua::client::Client::create(runtime.executor(),
    {.identity = ua::ApplicationIdentity::load_default(),
      .application = std::move(application),
      .client = ua::client::ClientConfig{}},
    {.crypto = pki.crypto, .applicationGroupCertificateStore = pki.store}));
}

/// Discovers the server's endpoints and opens a Session on the strongest one.
ua::client::Connection connect(ua::Runtime& runtime, std::string_view endpointUrl)
{
  // Identity, client, connection: the three steps every client performs, covered properly by
  // examples/client/minimal, gathered here so main() gets to the subject.
  const examples::DevelopmentPki pki =
    examples::open_development_pki(runtime.executor(), examples::PkiRole::Client);
  ua::client::Client& client = create_client(runtime, pki);
  ua::client::EasyConnectConfig policy;
  policy.endpointUrl = std::string{endpointUrl};
  policy.timeout = connectTimeout;
  return client.easy_connect_sync(std::move(policy));
}

/// Resolves a node beneath `Objects` from the BrowseNames on the path to it.
ua::NodeId resolve(ua::client::Connection& connection, const std::vector<std::string_view>& names)
{
  const std::uint16_t namespaceIndex = connection.namespace_table()->lookup_index(namespaceUri).value();
  return connection.typed().resolve_path_sync(ua::NodeId{ua::ObjectId::ObjectsFolder},
    ua::hierarchical_path(namespaceIndex, std::vector<std::string>(names.begin(), names.end())));
}

/// Names what a directory holds, in the order the server reported it.
///
/// Each entry is classified from its TypeDefinition, so a subdirectory and a file are distinguished
/// by what they *are* rather than by a guess at the BrowseName.
std::string list(ua::client::FileTransferClient& files, const ua::NodeId& directory)
{
  std::string names;
  for (const ua::client::FileSystemEntry& entry : files.list_directory_sync(directory))
  {
    names += names.empty() ? "" : ", ";
    names += fmt::format("{}{}",
      std::string_view{entry.browseName.name()},
      entry.kind == ua::client::FileSystemEntryKind::Directory ? "/" : "");
  }
  return names;
}

/// Converts the bytes of a file to text for printing.
std::string as_text(const ua::ByteString& content)
{
  std::string text;
  for (const std::uint8_t value : content)
  {
    text.push_back(static_cast<char>(value));
  }
  return text;
}

/// The bytes to write, as a ByteString.
ua::ByteString bytes_of(std::string_view text)
{
  ua::ByteString content;
  for (const char character : text)
  {
    content.push_back(static_cast<std::uint8_t>(character));
  }
  return content;
}

/// Renders file bytes on one line, so a file containing newlines does not break the step output.
std::string one_line(std::string text)
{
  for (char& character : text)
  {
    if (character == '\n' || character == '\r')
    {
      character = ' ';
    }
  }
  return text;
}

/// Reads a file the way a large one has to be read: a chunk at a time, through an open handle.
///
/// `read_all_sync` is the convenience for a file that fits in one response. Anything bigger is
/// Open, then Read until the server returns nothing, then Close - and the handle closes the
/// server-side one when it goes out of scope, so an abandoned transfer does not leak it.
std::string read_in_chunks(ua::client::FileTransferClient& files, const ua::NodeId& file)
{
  ua::client::FileHandle handle = files.open_sync(file, ua::client::FileOpenMode::Read);
  std::string content;
  for (ua::ByteString chunk = handle.read_sync(chunkBytes); !chunk.empty();
       chunk = handle.read_sync(chunkBytes))
  {
    content += as_text(chunk);
  }
  handle.close_sync();
  return content;
}

/// Reads the last @p bytes of a file by seeking, rather than reading everything before them.
///
/// A stream position is what makes a partial transfer possible: resuming an interrupted download,
/// or reading a trailer without paying for the whole file.
std::string read_tail(ua::client::FileTransferClient& files, const ua::NodeId& file, std::uint64_t from)
{
  ua::client::FileHandle handle = files.open_sync(file, ua::client::FileOpenMode::Read);
  handle.set_position_sync(from);
  const std::string tail = as_text(handle.read_sync(chunkBytes));
  handle.close_sync();
  return tail;
}

}  // namespace

int main(int argc, char** argv)
{
  try
  {
    examples::banner("client/file_transfer", "List, read, and create files through OPC UA.");

    const std::string_view endpointUrl = examples::option_value(argc, argv, "--endpoint", defaultEndpointUrl);

    ua::Runtime runtime{{.threads = 2}};
    ua::client::Connection connection = connect(runtime, endpointUrl);
    ua::client::FileTransferClient files = connection.files();
    const ua::NodeId documents = resolve(connection, {directoryName});
    examples::step(1, fmt::format("Connected to {} and resolved {}", endpointUrl, directoryName));

    examples::step(2, fmt::format("Directory holds: {}", list(files, documents)));

    const ua::NodeId manual = resolve(connection, {directoryName, seedFileName});
    const std::string content = as_text(files.read_all_sync(manual));
    examples::step(3, fmt::format("Read {} in one call, {} bytes", seedFileName, content.size()));
    examples::detail(fmt::format("First line: {}", content.substr(0, content.find('\n'))));

    const ua::NodeId created = files.create_file_sync(documents, ua::String{std::string{newFileName}});
    files.write_all_sync(created, bytes_of(newFileContent));
    examples::step(4, fmt::format("Created and wrote {}", newFileName));

    examples::step(5, fmt::format("Directory now holds: {}", list(files, documents)));

    // A directory is a node too, so creating one adds a node and needs AddNode permission - which
    // is why the server grants Operator rather than Observer.
    const ua::NodeId manuals =
      files.create_directory_sync(documents, ua::String{std::string{subdirectoryName}});
    files.write_all_sync(
      files.create_file_sync(manuals, ua::String{std::string{newFileName}}), bytes_of(newFileContent));
    examples::step(6, fmt::format("Created {}/ and a file inside it", subdirectoryName));
    examples::detail(fmt::format("{} holds: {}", subdirectoryName, list(files, manuals)));

    examples::step(7,
      fmt::format("Read {} a chunk at a time: {} bytes", seedFileName, read_in_chunks(files, manual).size()));
    examples::detail(fmt::format(
      "Seeked to byte {} and read on: {}", chunkBytes, one_line(read_tail(files, manual, chunkBytes))));

    // Deleting removes the node as well as the file, so the directory listing changes with it.
    files.delete_sync(documents, manuals);
    examples::step(
      8, fmt::format("Deleted {}/, directory now holds: {}", subdirectoryName, list(files, documents)));

    connection.close_sync();
    runtime.shutdown().value();
    examples::step(9, "Closed the Session and stopped the client");

    examples::finished("client/file_transfer");
    return 0;
  }
  catch (const ua::UaException& failure)
  {
    examples::print_failure("client/file_transfer", failure.status_code());
  }
  catch (const std::exception& failure)
  {
    fmt::print(stderr, "\nFAILED  client/file_transfer: {}\n", failure.what());
  }
  return 1;
}

// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "allocation_controller.h"

#include <cerrno>
#include <charconv>

#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <unistd.h>
#include <unwind.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <map>
#include <new>
#include <sstream>
#include <span>
#include <stdexcept>
#include <utility>

namespace ua::test::allocation
{
namespace
{

enum class Mode
{
  Off,
  Recording,
  Failing,
  FailingAll
};

struct Controller
{
  Mode mode{Mode::Off};
  bool tracing{false};
  std::size_t injections{0};
  std::size_t successfulAllocationsRemaining{0};
  bool overflow{false};
  std::uintptr_t target{0};
  std::size_t count{0};
  std::size_t recordingGeneration{0};
  std::array<Trace, 2048> traces{};
  Trace failure;
};

thread_local Controller gController;
thread_local std::size_t gSymbolizationGeneration{0};
thread_local std::map<std::string, std::vector<std::pair<std::uintptr_t, std::uintptr_t>>>
  gSymbolizationQueries;

_Unwind_Reason_Code capture_frame(_Unwind_Context* context, void* argument)
{
  auto& trace = *static_cast<Trace*>(argument);
  const auto address = static_cast<std::uintptr_t>(_Unwind_GetIP(context));
  if (address != 0 && trace.depth < trace.addresses.size())
  {
    trace.addresses[trace.depth++] = address;
    return _URC_NO_REASON;
  }
  return _URC_END_OF_STACK;
}

Trace capture(std::size_t bytes) noexcept
{
  Trace trace;
  trace.bytes = bytes;
  _Unwind_Backtrace(capture_frame, &trace);
  return trace;
}

void require_disarmed()
{
  if (armed())
  {
    throw std::logic_error{"Allocation evidence cannot be processed while interception is armed"};
  }
}

// Symbolization is outside the armed interval, and produces no temporary files or scripts.
std::map<std::uintptr_t, std::vector<Frame>> symbolize(std::span<const Trace> traces)
{
  require_disarmed();
  if (gSymbolizationGeneration != gController.recordingGeneration)
  {
    gSymbolizationQueries.clear();
    gSymbolizationGeneration = gController.recordingGeneration;
  }
  std::map<std::uintptr_t, std::vector<Frame>> frames;
  for (const auto& trace : traces)
  {
    for (std::size_t frame = 0; frame < trace.depth; ++frame)
    {
      frames.try_emplace(trace.addresses[frame]);
    }
  }
  std::map<std::string, std::vector<std::pair<std::uintptr_t, std::uintptr_t>>> modules;
  for (const auto& [address, inlineFrames] : frames)
  {
    Dl_info module{};
    // A stack address is a return PC; the preceding instruction belongs to the allocating call site.
    // Normalize PIE/shared-library addresses with the ELF type, not a compiler/linker assumption.
    std::uintptr_t offset = address - 1;
    std::string executable = "/proc/" + std::to_string(::getpid()) + "/exe";
    if (::dladdr(reinterpret_cast<void*>(address), &module) != 0 && module.dli_fbase != nullptr)
    {
      const auto* header = static_cast<const ElfW(Ehdr)*>(module.dli_fbase);
      if (header->e_type == ET_DYN)
      {
        offset -= reinterpret_cast<std::uintptr_t>(module.dli_fbase);
      }
      if (module.dli_fname != nullptr)
      {
        executable = module.dli_fname;
      }
    }
    modules[executable].emplace_back(address, offset);
  }
  for (const auto& [executable, addresses] : modules)
  {
    // GNU BFD can choose a different function alias after earlier address queries. Repeat the
    // complete calibration query sequence, then append new PCs, and decode every answer freshly.
    auto& queries = gSymbolizationQueries[executable];
    for (const auto& address : addresses)
    {
      if (std::none_of(queries.begin(),
            queries.end(),
            [&address](const auto& known) { return known.first == address.first; }))
      {
        queries.push_back(address);
      }
    }
    // Paths come from the loader/configure, but still require shell quoting at this C API boundary.
    const auto quote = [](std::string_view path)
    {
      std::string quoted{"'"};
      for (const char character : path)
      {
        if (character == '\'')
        {
          quoted += "'\\''";
        }
        else
        {
          quoted += character;
        }
      }
      return quoted + "'";
    };
    std::ostringstream command;
    command << quote(UASDK_ALLOCATION_ADDR2LINE) << " -a -i -f -C -e " << quote(executable);
    std::vector<std::uintptr_t> offsets;
    for (const auto& [address, offset] : queries)
    {
      command << " 0x" << std::hex << offset;
      offsets.push_back(offset);
    }
    std::FILE* pipe = ::popen(command.str().c_str(), "r");
    if (pipe == nullptr)
    {
      throw std::runtime_error{"Unable to start the required addr2line symbolizer"};
    }
    try
    {
      std::string output;
      std::array<char, 4096> buffer{};
      while (std::fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr)
      {
        output += buffer.data();
      }
      if (std::ferror(pipe))
      {
        throw std::runtime_error{"Unable to read the allocation symbolizer output"};
      }
      std::vector<std::vector<Frame>> decoded;
      try
      {
        decoded = parse_symbolizer_output(output, offsets);
      }
      catch (const std::runtime_error& error)
      {
        throw std::runtime_error{std::string{error.what()} + "\naddr2line command: " + command.str()};
      }
      for (std::size_t index = 0; index < queries.size(); ++index)
      {
        const auto address = queries[index].first;
        if (auto found = frames.find(address); found != frames.end())
        {
          for (auto& frame : decoded[index])
            frame.address = address;
          found->second = std::move(decoded[index]);
        }
      }
    }
    catch (...)
    {
      ::pclose(pipe);
      throw;
    }
    if (::pclose(pipe) != 0)
    {
      throw std::runtime_error{"addr2line failed to identify the allocation call sites"};
    }
  }
  return frames;
}

std::optional<Evidence> identify(
  const Trace& trace, const std::map<std::uintptr_t, std::vector<Frame>>& frames)
{
  std::vector<Frame> copyWrappers;
  for (std::size_t index = 0; index < trace.depth; ++index)
  {
    auto inlineFrames = frames.at(trace.addresses[index]);
    for (auto& frame : inlineFrames)
    {
      if (frame.file.find("/sdk/implementation/") == std::string::npos)
        continue;
      std::ifstream source{frame.file};
      if (!source)
      {
        throw std::runtime_error{
          "SDK source is required for the continuation allocation location proof: " + frame.file};
      }
      for (std::size_t line = 1; line <= frame.line; ++line)
      {
        if (!std::getline(source, frame.statement))
        {
          throw std::runtime_error{"The symbolized SDK allocation source line is unavailable"};
        }
      }
    }
    // NodeId's out-of-line value copy is transparent to the allocation-staging call site. No routing,
    // Node interpretation or completion-assembly function is transparent. Record every skipped wrapper.
    for (const auto& frame : inlineFrames)
    {
      if (frame.file.find("/sdk/implementation/") == std::string::npos)
        continue;
      if (frame.file.ends_with("ua_node_id.cpp") &&
          (frame.function == "ua::NodeId::NodeId(ua::NodeId const&)" ||
            frame.function == "ua::NodeId::operator=(ua::NodeId const&)"))
      {
        copyWrappers.push_back(frame);
        continue;
      }
      return Evidence{trace, frame, std::move(copyWrappers), std::move(inlineFrames)};
    }
  }
  return std::nullopt;
}

}  // namespace

std::vector<std::vector<Frame>> parse_symbolizer_output(
  std::string_view output, std::span<const std::uintptr_t> expectedAddresses)
{
  require_disarmed();
  if (!output.empty() && output.back() != '\n')
    throw std::runtime_error{"Truncated addr2line output"};
  std::vector<std::string> lines;
  std::istringstream input{std::string{output}};
  for (std::string line; std::getline(input, line);)
    lines.push_back(std::move(line));
  // The native module reply identifies these external fmt functions. Include the 32-bit size_t
  // spelling of the same buffer-growth method. An unqualified name or another specialization
  // cannot establish external ownership.
  constexpr std::array<std::string_view, 6> externalFunctionsWithUnknownLocations{
    "fmt::v10::vformat[abi:cxx11](fmt::v10::basic_string_view<char>, "
    "fmt::v10::basic_format_args<fmt::v10::basic_format_context<fmt::v10::appender, char> >)",
    "fmt::v10::basic_memory_buffer<char, 500ul, std::allocator<char> >::grow(unsigned long)",
    "fmt::v10::basic_memory_buffer<char, 500u, std::allocator<char> >::grow(unsigned int)",
    "fmt::v10::appender fmt::v10::detail::copy_str_noinline<char, char const*, fmt::v10::appender>(char "
    "const*, char const*, fmt::v10::appender)",
    "char const* fmt::v10::detail::parse_replacement_field<char, "
    "fmt::v10::detail::vformat_to<char>(fmt::v10::detail::buffer<char>&, fmt::v10::basic_string_view<char>, "
    "fmt::v10::detail::vformat_args<char>::type, fmt::v10::detail::locale_ref)::format_handler&>(char "
    "const*, char const*, fmt::v10::detail::vformat_to<char>(fmt::v10::detail::buffer<char>&, "
    "fmt::v10::basic_string_view<char>, fmt::v10::detail::vformat_args<char>::type, "
    "fmt::v10::detail::locale_ref)::format_handler&)",
    "void fmt::v10::detail::vformat_to<char>(fmt::v10::detail::buffer<char>&, "
    "fmt::v10::basic_string_view<char>, fmt::v10::detail::vformat_args<char>::type, "
    "fmt::v10::detail::locale_ref)"};
  const auto number = [](std::string_view text, int base)
  {
    std::uintptr_t value{0};
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value, base);
    if (text.empty() || parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size())
      throw std::runtime_error{"Invalid addr2line numeric field"};
    return value;
  };
  std::vector<std::vector<Frame>> result;
  std::size_t position{0};
  for (const auto expected : expectedAddresses)
  {
    const auto recordBegin = position;
    if (position == lines.size() || !lines[position].starts_with("0x") ||
        number(std::string_view{lines[position]}.substr(2), 16) != expected)
      throw std::runtime_error{"Missing or mismatched addr2line address"};
    ++position;
    std::vector<Frame> inlineFrames;
    while (position < lines.size() && !lines[position].starts_with("0x"))
    {
      Frame frame;
      frame.address = expected;
      frame.function = lines[position++];
      if (frame.function.empty() || position == lines.size() || lines[position].starts_with("0x"))
        throw std::runtime_error{"Incomplete addr2line inline frame"};
      frame.sourceLocation = lines[position++];
      const auto colon = frame.sourceLocation.rfind(':');
      // The retained fmt record has an empty filename and unknown line. Preserve those raw
      // fields without claiming SDK source evidence or accepting other empty filename forms.
      const bool unknownExternalLocation =
        frame.sourceLocation == ":?" &&
        std::find(externalFunctionsWithUnknownLocations.begin(),
          externalFunctionsWithUnknownLocations.end(),
          std::string_view{frame.function}) != externalFunctionsWithUnknownLocations.end();
      if (colon == std::string::npos || (colon == 0 && !unknownExternalLocation))
      {
        std::ostringstream diagnostic;
        diagnostic << "Invalid addr2line source location; query[" << result.size() << "] expected=0x"
                   << std::hex << expected << "\nfunction: " << frame.function
                   << "\nlocation: " << frame.sourceLocation << "\ncomplete rejected record:\n";
        for (auto recordLine = recordBegin; recordLine < lines.size(); ++recordLine)
        {
          if (recordLine != recordBegin && lines[recordLine].starts_with("0x"))
            break;
          diagnostic << lines[recordLine] << '\n';
        }
        throw std::runtime_error{diagnostic.str()};
      }
      frame.file = frame.sourceLocation.substr(0, colon);
      const auto suffix = std::string_view{frame.sourceLocation}.substr(colon + 1);
      if (suffix != "?")
      {
        const auto end = suffix.find_first_not_of("0123456789");
        frame.line = number(suffix.substr(0, end), 10);
        if (end != std::string_view::npos)
        {
          const auto discriminator = suffix.substr(end);
          constexpr std::string_view prefix{" (discriminator "};
          if (!discriminator.starts_with(prefix) || !discriminator.ends_with(')'))
            throw std::runtime_error{"Invalid addr2line discriminator"};
          static_cast<void>(
            number(discriminator.substr(prefix.size(), discriminator.size() - prefix.size() - 1), 10));
        }
      }
      if (frame.file.find("/sdk/implementation/") != std::string::npos &&
          (frame.line == 0 || frame.function == "??"))
        throw std::runtime_error{"SDK allocation frame has no required debug-symbol evidence"};
      inlineFrames.push_back(std::move(frame));
    }
    if (inlineFrames.empty())
      throw std::runtime_error{"addr2line address has no inline frames"};
    result.push_back(std::move(inlineFrames));
  }
  if (position != lines.size())
    throw std::runtime_error{"Unexpected trailing addr2line output"};
  return result;
}

void before_allocation(std::size_t bytes)
{
  if (gController.mode == Mode::Off || gController.tracing)
  {
    return;
  }
  if (gController.mode == Mode::FailingAll)
  {
    if (gController.successfulAllocationsRemaining != 0)
    {
      --gController.successfulAllocationsRemaining;
      return;
    }
    ++gController.injections;
    throw std::bad_alloc{};
  }
  gController.tracing = true;
  const Trace trace = capture(bytes);
  gController.tracing = false;
  if (gController.mode == Mode::Recording)
  {
    if (gController.count == gController.traces.size())
    {
      gController.overflow = true;
    }
    else
    {
      gController.traces[gController.count++] = trace;
    }
    return;
  }
  if (std::find(trace.addresses.begin(), trace.addresses.begin() + trace.depth, gController.target) !=
      trace.addresses.begin() + trace.depth)
  {
    gController.failure = trace;
    ++gController.injections;
    gController.mode = Mode::Off;
    throw std::bad_alloc{};
  }
}

void record() noexcept
{
  ++gController.recordingGeneration;
  gController.count = 0;
  gController.overflow = false;
  gController.injections = 0;
  gController.mode = Mode::Recording;
}

void fail_at(std::uintptr_t address) noexcept
{
  gController.target = address;
  gController.injections = 0;
  gController.mode = Mode::Failing;
}

void fail_all(std::size_t successfulAllocations) noexcept
{
  gController.injections = 0;
  gController.successfulAllocationsRemaining = successfulAllocations;
  gController.mode = Mode::FailingAll;
}

void disarm() noexcept
{
  gController.mode = Mode::Off;
}

bool armed() noexcept
{
  return gController.mode != Mode::Off;
}

std::size_t injections() noexcept
{
  return gController.injections;
}

bool overflowed() noexcept
{
  return gController.overflow;
}

Trace failed_allocation() noexcept
{
  return gController.failure;
}

std::vector<Evidence> recorded_sdk_allocations()
{
  require_disarmed();
  const std::span<const Trace> traces{gController.traces.data(), gController.count};
  const auto frames = symbolize(traces);
  std::vector<Evidence> result;
  for (const auto& trace : traces)
  {
    if (auto evidence = identify(trace, frames))
    {
      result.push_back(std::move(*evidence));
    }
  }
  return result;
}

std::optional<Evidence> identify(const Trace& trace)
{
  return identify(trace, symbolize(std::span<const Trace>{&trace, 1}));
}

std::string describe(const Evidence& evidence)
{
  std::ostringstream description;
  description << evidence.nearestSdkFrame.file << ':' << evidence.nearestSdkFrame.line << " ("
              << evidence.allocation.bytes << " bytes): " << evidence.nearestSdkFrame.statement << " ["
              << evidence.nearestSdkFrame.function << ']';
  for (const auto& wrapper : evidence.copyWrappers)
  {
    description << " via " << wrapper.file << ':' << wrapper.line << " [" << wrapper.function << ']';
  }
  for (const auto& frame : evidence.inlineFrames)
  {
    description << " inline " << frame.sourceLocation << " [" << frame.function << ']';
  }
  description << " allocation stack:";
  for (std::size_t frame = 0; frame < evidence.allocation.depth; ++frame)
  {
    description << " 0x" << std::hex << evidence.allocation.addresses[frame];
  }
  return description.str();
}

}  // namespace ua::test::allocation

namespace
{

void* allocate(std::size_t bytes, std::size_t alignment = alignof(std::max_align_t))
{
  ua::test::allocation::before_allocation(bytes);
  bytes = std::max(bytes, std::size_t{1});
  for (;;)
  {
    void* memory = nullptr;
    if (alignment <= alignof(std::max_align_t))
    {
      memory = std::malloc(bytes);
    }
    else if (::posix_memalign(&memory, alignment, bytes) != 0)
    {
      memory = nullptr;
    }
    if (memory != nullptr)
    {
      return memory;
    }
    if (const auto handler = std::get_new_handler())
    {
      handler();
    }
    else
    {
      throw std::bad_alloc{};
    }
  }
}

}  // namespace

// This private executable also intercepts Asio's C allocation path. The GNU linker redirects only
// references from this executable and its static archives; libc's allocator remains unchanged.
extern "C" void* real_aligned_alloc(std::size_t alignment, std::size_t bytes) noexcept
  asm("__real_aligned_alloc");
extern "C" void* wrap_aligned_alloc(std::size_t alignment, std::size_t bytes) noexcept
  asm("__wrap_aligned_alloc");

extern "C" void* wrap_aligned_alloc(std::size_t alignment, std::size_t bytes) noexcept
{
  try
  {
    ua::test::allocation::before_allocation(bytes);
  }
  catch (...)
  {
    errno = ENOMEM;
    return nullptr;
  }
  return real_aligned_alloc(alignment, bytes);
}

void* operator new(std::size_t bytes)
{
  return allocate(bytes);
}

void* operator new[](std::size_t bytes)
{
  return allocate(bytes);
}

void* operator new(std::size_t bytes, std::align_val_t alignment)
{
  return allocate(bytes, static_cast<std::size_t>(alignment));
}

void* operator new[](std::size_t bytes, std::align_val_t alignment)
{
  return allocate(bytes, static_cast<std::size_t>(alignment));
}

void* operator new(std::size_t bytes, const std::nothrow_t&) noexcept
{
  try
  {
    return allocate(bytes);
  }
  catch (...)
  {
    return nullptr;
  }
}

void* operator new[](std::size_t bytes, const std::nothrow_t&) noexcept
{
  try
  {
    return allocate(bytes);
  }
  catch (...)
  {
    return nullptr;
  }
}

void* operator new(std::size_t bytes, std::align_val_t alignment, const std::nothrow_t&) noexcept
{
  try
  {
    return allocate(bytes, static_cast<std::size_t>(alignment));
  }
  catch (...)
  {
    return nullptr;
  }
}

void* operator new[](std::size_t bytes, std::align_val_t alignment, const std::nothrow_t&) noexcept
{
  try
  {
    return allocate(bytes, static_cast<std::size_t>(alignment));
  }
  catch (...)
  {
    return nullptr;
  }
}

void operator delete(void* memory) noexcept
{
  std::free(memory);
}

void operator delete[](void* memory) noexcept
{
  std::free(memory);
}

void operator delete(void* memory, std::size_t) noexcept
{
  std::free(memory);
}

void operator delete[](void* memory, std::size_t) noexcept
{
  std::free(memory);
}

void operator delete(void* memory, std::align_val_t) noexcept
{
  std::free(memory);
}

void operator delete[](void* memory, std::align_val_t) noexcept
{
  std::free(memory);
}

void operator delete(void* memory, std::size_t, std::align_val_t) noexcept
{
  std::free(memory);
}

void operator delete[](void* memory, std::size_t, std::align_val_t) noexcept
{
  std::free(memory);
}

void operator delete(void* memory, const std::nothrow_t&) noexcept
{
  std::free(memory);
}

void operator delete[](void* memory, const std::nothrow_t&) noexcept
{
  std::free(memory);
}

void operator delete(void* memory, std::align_val_t, const std::nothrow_t&) noexcept
{
  std::free(memory);
}

void operator delete[](void* memory, std::align_val_t, const std::nothrow_t&) noexcept
{
  std::free(memory);
}

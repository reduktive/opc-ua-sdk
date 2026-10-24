// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UASDK_TESTS_FIRE_AND_FORGET_SCANNER_H
#define UASDK_TESTS_FIRE_AND_FORGET_SCANNER_H

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <map>
#include <ranges>
#include <regex>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace ua::test_helpers::fire_and_forget
{

struct ScanResult
{
  std::vector<std::string> stubs;
  std::vector<std::string> governed;
  std::vector<std::string> unjustified;
};

inline bool is_identifier_character(char candidate)
{
  return std::isalnum(static_cast<unsigned char>(candidate)) != 0 || candidate == '_';
}

inline std::string lowercased(std::string text)
{
  std::ranges::transform(text,
    text.begin(),
    [](char character) { return static_cast<char>(std::tolower(static_cast<unsigned char>(character))); });
  return text;
}

inline std::string mask_comments_and_literals(std::string_view source)
{
  enum class State
  {
    Code,
    LineComment,
    BlockComment,
    StringLiteral,
    CharacterLiteral,
  };

  std::string masked{source};
  State state = State::Code;
  bool escaped = false;
  for (size_t index = 0; index < source.size(); ++index)
  {
    const char current = source[index];
    const char next = index + 1 < source.size() ? source[index + 1] : '\0';
    if (state == State::Code)
    {
      if (current == 'R' && next == '"')
      {
        const auto delimiterEnd = source.find('(', index + 2);
        if (delimiterEnd != std::string_view::npos && delimiterEnd - (index + 2) <= 16)
        {
          const std::string delimiter{source.substr(index + 2, delimiterEnd - (index + 2))};
          const std::string terminator = ")" + delimiter + "\"";
          const auto literalEnd = source.find(terminator, delimiterEnd + 1);
          if (literalEnd != std::string_view::npos)
          {
            const auto afterLiteral = literalEnd + terminator.size();
            for (size_t cursor = index; cursor < afterLiteral; ++cursor)
            {
              if (masked[cursor] != '\n' && masked[cursor] != '\r')
                masked[cursor] = ' ';
            }
            index = afterLiteral - 1;
            continue;
          }
        }
      }
      if (current == '/' && next == '/')
      {
        masked[index] = masked[index + 1] = ' ';
        ++index;
        state = State::LineComment;
      }
      else if (current == '/' && next == '*')
      {
        masked[index] = masked[index + 1] = ' ';
        ++index;
        state = State::BlockComment;
      }
      else if (current == '"')
      {
        masked[index] = ' ';
        state = State::StringLiteral;
        escaped = false;
      }
      else if (current == '\'')
      {
        masked[index] = ' ';
        state = State::CharacterLiteral;
        escaped = false;
      }
      continue;
    }

    if (current != '\n' && current != '\r')
      masked[index] = ' ';

    if (state == State::LineComment && current == '\n')
      state = State::Code;
    else if (state == State::BlockComment && current == '*' && next == '/')
    {
      masked[index + 1] = ' ';
      ++index;
      state = State::Code;
    }
    else if (state == State::StringLiteral || state == State::CharacterLiteral)
    {
      if (escaped)
        escaped = false;
      else if (current == '\\')
        escaped = true;
      else if ((state == State::StringLiteral && current == '"') ||
               (state == State::CharacterLiteral && current == '\''))
        state = State::Code;
    }
  }
  return masked;
}

inline std::vector<std::string> split_lines(std::string_view source)
{
  std::vector<std::string> lines;
  std::istringstream input{std::string{source}};
  for (std::string line; std::getline(input, line);)
    lines.push_back(std::move(line));
  return lines;
}

inline bool is_comment_line(std::string_view line)
{
  const auto first = line.find_first_not_of(" \t");
  if (first == std::string_view::npos)
    return true;
  return line.substr(first).starts_with("//") || line.substr(first).starts_with("/*") || line[first] == '*';
}

inline std::string comment_block_above(const std::vector<std::string>& lines, size_t line)
{
  std::string block;
  for (size_t above = line; above-- > 0;)
  {
    if (lines[above].find_first_not_of(" \t") == std::string::npos || !is_comment_line(lines[above]))
      break;
    block = lowercased(lines[above]) + "\n" + block;
  }
  return block;
}

struct EnclosingFunction
{
  std::string name;
  size_t line{};
};

inline EnclosingFunction enclosing_function(const std::vector<std::string>& lines, size_t line)
{
  for (size_t above = std::min(line + 1, lines.size()); above-- > 0;)
  {
    const auto& candidate = lines[above];
    if (candidate.empty() || is_comment_line(candidate))
      continue;
    const char first = candidate.front();
    if (first == ' ' || first == '\t' || first == '#' || first == '{' || first == '}')
      continue;
    const auto paren = candidate.find('(');
    if (paren == std::string::npos)
      continue;
    size_t nameBegin = paren;
    while (nameBegin > 0 && is_identifier_character(candidate[nameBegin - 1]))
      --nameBegin;
    if (nameBegin == paren)
      continue;
    return {candidate.substr(nameBegin, paren - nameBegin), above};
  }
  return {};
}

inline size_t statement_start(const std::vector<std::string>& lines, size_t line)
{
  size_t start = line;
  while (start > 0)
  {
    const auto& previous = lines[start - 1];
    if (is_comment_line(previous))
      break;
    if (previous.find(';') != std::string::npos || previous.find('{') != std::string::npos ||
        previous.find('}') != std::string::npos)
      break;
    --start;
  }
  return start;
}

inline size_t line_at(std::string_view source, size_t position)
{
  return static_cast<size_t>(
    std::count(source.begin(), source.begin() + static_cast<std::ptrdiff_t>(position), '\n'));
}

inline bool has_justification(std::string documentation)
{
  static constexpr std::string_view markers[]{"fire-and-forget",
    "fire and forget",
    "best-effort",
    "best effort",
    "advisory",
    "no use for the result",
    "result is unused",
    "result is not needed",
    "result is discarded",
    "discard the result"};
  documentation = lowercased(std::move(documentation));
  return std::ranges::any_of(markers,
    [&documentation](std::string_view marker) { return documentation.find(marker) != std::string::npos; });
}

// An unqualified declaration name is safe evidence only when it identifies exactly one declaration
// in the scanned SDK headers. Generated type families deliberately repeat names such as
// `remove_async`; concatenating their comments would let an unrelated overload justify the caller.
using DeclarationDocumentation = std::map<std::string, std::vector<std::string>>;

inline ScanResult scan_source(std::string_view rawSource, std::string_view relative,
  const DeclarationDocumentation& declarationDocumentation = {})
{
  static const std::regex emptyResultCallback{
    R"(\[([^\]]*)\]\s*\(\s*([^()]*)\)\s*(?:mutable\s*)?(?:noexcept(?:\s*\([^)]*\))?\s*)?(?:->\s*[^\{]+)?\{\s*\})"};

  const std::string masked = mask_comments_and_literals(rawSource);
  const auto lines = split_lines(rawSource);
  ScanResult result;
  for (auto match = std::sregex_iterator{masked.begin(), masked.end(), emptyResultCallback};
       match != std::sregex_iterator{};
       ++match)
  {
    const std::string parameters = (*match)[2].str();
    if (parameters.find("Result") == std::string::npos &&
        !std::regex_search(parameters, std::regex{R"(\bauto\b)"}))
      continue;

    const size_t matchPosition = static_cast<size_t>(match->position());
    const size_t line = line_at(masked, matchPosition);
    const std::string site = std::string{relative} + ":" + std::to_string(line + 1);
    result.stubs.push_back(site);

    const auto function = enclosing_function(lines, line);
    if (!function.name.ends_with("_async"))
      continue;
    result.governed.push_back(site);

    std::string documentation = comment_block_above(lines, statement_start(lines, line));
    documentation += comment_block_above(lines, function.line);
    if (const auto declaration = declarationDocumentation.find(function.name);
        declaration != declarationDocumentation.end() && declaration->second.size() == 1)
      documentation += declaration->second.front();

    if (!has_justification(std::move(documentation)))
      result.unjustified.push_back(site);
  }
  return result;
}

inline std::vector<std::filesystem::path> source_files(
  const std::filesystem::path& root, std::string_view extension)
{
  std::vector<std::filesystem::path> files;
  if (!std::filesystem::exists(root))
    return files;
  for (const auto& entry : std::filesystem::recursive_directory_iterator{
         root, std::filesystem::directory_options::skip_permission_denied})
  {
    if (entry.is_regular_file() && entry.path().extension() == extension)
      files.push_back(entry.path());
  }
  std::ranges::sort(files);
  return files;
}

inline std::string read_file(const std::filesystem::path& file)
{
  std::ifstream input{file};
  std::ostringstream contents;
  contents << input.rdbuf();
  return contents.str();
}

inline DeclarationDocumentation declaration_documentation(const std::filesystem::path& sdkRoot)
{
  DeclarationDocumentation documentation;
  for (const auto& file : source_files(sdkRoot, ".h"))
  {
    const auto lines = split_lines(read_file(file));
    for (size_t line = 0; line < lines.size(); ++line)
    {
      const auto paren = lines[line].find('(');
      if (paren == std::string::npos || is_comment_line(lines[line]))
        continue;
      size_t nameBegin = paren;
      while (nameBegin > 0 && is_identifier_character(lines[line][nameBegin - 1]))
        --nameBegin;
      if (nameBegin == paren)
        continue;
      const std::string name = lines[line].substr(nameBegin, paren - nameBegin);
      if (!name.ends_with("_async"))
        continue;

      size_t declarationStart = line;
      while (declarationStart > 0)
      {
        const auto& previous = lines[declarationStart - 1];
        if (is_comment_line(previous) || previous.find_first_not_of(" \t") == std::string::npos ||
            previous.find(';') != std::string::npos || previous.find('{') != std::string::npos ||
            previous.find('}') != std::string::npos || previous.starts_with('#'))
          break;
        --declarationStart;
      }
      documentation[name].push_back(comment_block_above(lines, declarationStart));
    }
  }
  return documentation;
}

inline ScanResult scan_repository(const std::filesystem::path& repositoryRoot)
{
  const auto sdkRoot = repositoryRoot / "sdk";
  const auto declarations = declaration_documentation(sdkRoot);
  ScanResult aggregate;
  for (const auto& file : source_files(sdkRoot / "implementation", ".cpp"))
  {
    const auto relative = std::filesystem::relative(file, repositoryRoot).generic_string();
    auto fileResult = scan_source(read_file(file), relative, declarations);
    aggregate.stubs.insert(aggregate.stubs.end(), fileResult.stubs.begin(), fileResult.stubs.end());
    aggregate.governed.insert(
      aggregate.governed.end(), fileResult.governed.begin(), fileResult.governed.end());
    aggregate.unjustified.insert(
      aggregate.unjustified.end(), fileResult.unjustified.begin(), fileResult.unjustified.end());
  }
  return aggregate;
}

}  // namespace ua::test_helpers::fire_and_forget

#endif  // UASDK_TESTS_FIRE_AND_FORGET_SCANNER_H

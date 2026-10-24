// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UASDK_TESTS_SERVER_ASYNC_SURFACE_CATALOGUE_H
#define UASDK_TESTS_SERVER_ASYNC_SURFACE_CATALOGUE_H

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <map>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace ua::test_helpers::server_async_catalogue
{

inline constexpr std::string_view propagatesResult = "propagates_result";
inline constexpr std::string_view locallyGeneratedResult = "locally_generated_result";
inline constexpr std::string_view fireAndForget = "fire_and_forget";
inline constexpr std::string_view privateContinuation = "private_continuation";
inline constexpr std::string_view outboundLifecycle = "outbound_lifecycle";

struct Row
{
  std::string identity;
  std::string classification;
  std::string criterion;
  std::string test;
};

using TestRelations = std::map<std::string, std::set<std::string>>;

struct ClassScope
{
  size_t begin{};
  size_t end{};
  std::string name;
};

inline bool is_identifier_character(char candidate)
{
  return std::isalnum(static_cast<unsigned char>(candidate)) != 0 || candidate == '_';
}

inline std::string strip_comments_and_literals(std::string_view source)
{
  enum class State
  {
    Code,
    LineComment,
    BlockComment,
    StringLiteral,
    CharacterLiteral,
  };

  State state = State::Code;
  bool escaped = false;
  std::string stripped{source};
  for (size_t index = 0; index < source.size(); ++index)
  {
    const char current = source[index];
    const char next = index + 1 < source.size() ? source[index + 1] : '\0';
    if (state == State::Code)
    {
      if (current == '/' && next == '/')
      {
        stripped[index] = stripped[index + 1] = ' ';
        ++index;
        state = State::LineComment;
      }
      else if (current == '/' && next == '*')
      {
        stripped[index] = stripped[index + 1] = ' ';
        ++index;
        state = State::BlockComment;
      }
      else if (current == '"')
      {
        stripped[index] = ' ';
        state = State::StringLiteral;
        escaped = false;
      }
      else if (current == '\'')
      {
        stripped[index] = ' ';
        state = State::CharacterLiteral;
        escaped = false;
      }
      continue;
    }

    if (current != '\n' && current != '\r')
      stripped[index] = ' ';

    if (state == State::LineComment && current == '\n')
      state = State::Code;
    else if (state == State::BlockComment && current == '*' && next == '/')
    {
      stripped[index + 1] = ' ';
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
  return stripped;
}

inline std::vector<ClassScope> derive_class_scopes(std::string_view source)
{
  static const std::regex classDefinition{R"(\b(class|struct)\s+([A-Za-z_][A-Za-z0-9_]*)[^;{}]*\{)"};
  std::vector<ClassScope> scopes;
  const std::string ownedSource{source};
  for (auto match = std::sregex_iterator{ownedSource.begin(), ownedSource.end(), classDefinition};
       match != std::sregex_iterator{};
       ++match)
  {
    const size_t definitionBegin = static_cast<size_t>(match->position());
    const size_t keywordBegin =
      definitionBegin + static_cast<size_t>((*match)[1].first - match->prefix().second);
    const auto beforeKeyword = ownedSource.substr(0, keywordBegin);
    const auto precedingWordEnd = beforeKeyword.find_last_not_of(" \t\r\n");
    if (precedingWordEnd != std::string::npos)
    {
      const auto precedingWordBegin = beforeKeyword.find_last_not_of(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_", precedingWordEnd);
      const auto precedingWord =
        beforeKeyword.substr(precedingWordBegin == std::string::npos ? 0 : precedingWordBegin + 1,
          precedingWordEnd - (precedingWordBegin == std::string::npos ? 0 : precedingWordBegin + 1) + 1);
      if (precedingWord == "enum")
        continue;
    }

    const size_t openBrace = definitionBegin + static_cast<size_t>(match->length()) - 1;
    size_t depth = 1;
    size_t closeBrace = openBrace + 1;
    for (; closeBrace < source.size() && depth != 0; ++closeBrace)
    {
      if (source[closeBrace] == '{')
        ++depth;
      else if (source[closeBrace] == '}')
        --depth;
    }
    if (depth == 0)
      scopes.push_back({openBrace + 1, closeBrace - 1, (*match)[2].str()});
  }
  return scopes;
}

inline std::string declaring_class(const std::vector<ClassScope>& scopes, size_t position)
{
  const ClassScope* innermost = nullptr;
  for (const auto& scope : scopes)
  {
    if (scope.begin <= position && position < scope.end &&
        (!innermost || scope.end - scope.begin < innermost->end - innermost->begin))
      innermost = &scope;
  }
  return innermost ? innermost->name : "<free>";
}

inline std::vector<std::string> derive_from_source(std::string_view rawSource, std::string_view relative)
{
  const std::string source = strip_comments_and_literals(rawSource);
  const auto scopes = derive_class_scopes(source);
  std::map<std::string, size_t> ordinals;
  std::vector<std::string> identities;
  size_t search = 0;
  while ((search = source.find("_async", search)) != std::string::npos)
  {
    const size_t marker = search;
    size_t nameBegin = marker;
    while (nameBegin > 0 && is_identifier_character(source[nameBegin - 1]))
      --nameBegin;
    size_t afterName = marker + std::string_view{"_async"}.size();
    while (afterName < source.size() && std::isspace(static_cast<unsigned char>(source[afterName])) != 0)
      ++afterName;
    search = marker + std::string_view{"_async"}.size();
    if (nameBegin == marker || afterName >= source.size() || source[afterName] != '(')
      continue;
    if (nameBegin > 0 && (source[nameBegin - 1] == '.' || source[nameBegin - 1] == '>'))
      continue;

    const size_t lineBegin =
      source.rfind('\n', nameBegin) == std::string::npos ? 0 : source.rfind('\n', nameBegin) + 1;
    const std::string_view prefix{source.data() + lineBegin, nameBegin - lineBegin};
    const bool hasReturnType = std::any_of(prefix.begin(), prefix.end(), is_identifier_character);
    if (!hasReturnType || prefix.find('=') != std::string_view::npos)
      continue;

    const std::string method = source.substr(nameBegin, afterName - nameBegin);
    const std::string owner = declaring_class(scopes, nameBegin);
    const size_t ordinal = ++ordinals[owner + "::" + method];
    identities.push_back(
      std::string{relative} + "::" + owner + "::" + method + "#" + std::to_string(ordinal));
  }
  return identities;
}

inline std::vector<std::string> derive_from_header(
  const std::filesystem::path& repositoryRoot, const std::filesystem::path& header)
{
  std::ifstream input{header};
  std::ostringstream buffer;
  buffer << input.rdbuf();
  const std::string relative = std::filesystem::relative(header, repositoryRoot).generic_string();
  return derive_from_source(buffer.str(), relative);
}

inline std::vector<std::string> derive(const std::filesystem::path& repositoryRoot)
{
  std::vector<std::string> identities;
  for (const auto& relativeRoot : {std::filesystem::path{"sdk/implementation/server"},
         std::filesystem::path{"sdk/implementation/address_space"}})
  {
    const auto root = repositoryRoot / relativeRoot;
    for (const auto& entry : std::filesystem::recursive_directory_iterator{root})
    {
      if (!entry.is_regular_file() || entry.path().extension() != ".h")
        continue;
      auto fromHeader = derive_from_header(repositoryRoot, entry.path());
      identities.insert(identities.end(), fromHeader.begin(), fromHeader.end());
    }
  }
  std::sort(identities.begin(), identities.end());
  return identities;
}

inline std::vector<Row> read_manifest(const std::filesystem::path& path)
{
  std::ifstream input{path};
  std::vector<Row> rows;
  std::string line;
  bool first = true;
  while (std::getline(input, line))
  {
    if (first)
    {
      first = false;
      continue;
    }
    if (line.empty())
      continue;
    std::vector<std::string> fields;
    size_t begin = 0;
    for (;;)
    {
      const size_t tab = line.find('\t', begin);
      fields.push_back(line.substr(begin, tab == std::string::npos ? tab : tab - begin));
      if (tab == std::string::npos)
        break;
      begin = tab + 1;
    }
    fields.resize(4);
    rows.push_back({std::move(fields[0]), std::move(fields[1]), std::move(fields[2]), std::move(fields[3])});
  }
  return rows;
}

inline std::set<std::string> declared_criteria(const std::filesystem::path& repositoryRoot)
{
  std::set<std::string> criteria;
  for (const auto& entry : std::filesystem::directory_iterator{repositoryRoot / "internal" / "requirements"})
  {
    if (!entry.is_regular_file() || entry.path().extension() != ".sdoc")
      continue;
    std::ifstream input{entry.path()};
    std::string line;
    while (std::getline(input, line))
    {
      constexpr std::string_view prefix = "UID: AC-";
      if (line.starts_with(prefix))
        criteria.insert(line.substr(std::string_view{"UID: "}.size()));
    }
  }
  return criteria;
}

inline bool parse_test_macro(std::string_view source, size_t position, std::string& test)
{
  constexpr std::string_view testMacro = "TEST(";
  constexpr std::string_view fixtureTestMacro = "TEST_F(";
  constexpr std::string_view parameterizedTestMacro = "TEST_P(";
  std::string_view prefix;
  for (const auto candidate : {testMacro, fixtureTestMacro, parameterizedTestMacro})
  {
    if (source.substr(position).starts_with(candidate))
    {
      prefix = candidate;
      break;
    }
  }
  if (prefix.empty() || (position > 0 && is_identifier_character(source[position - 1])))
    return false;

  size_t cursor = position + prefix.size();
  const auto parseIdentifier = [&source, &cursor]() -> std::string
  {
    while (cursor < source.size() && std::isspace(static_cast<unsigned char>(source[cursor])) != 0)
      ++cursor;
    const size_t begin = cursor;
    while (cursor < source.size() && is_identifier_character(source[cursor]))
      ++cursor;
    return std::string{source.substr(begin, cursor - begin)};
  };

  const std::string suite = parseIdentifier();
  while (cursor < source.size() && std::isspace(static_cast<unsigned char>(source[cursor])) != 0)
    ++cursor;
  if (suite.empty() || cursor >= source.size() || source[cursor] != ',')
    return false;
  ++cursor;
  const std::string name = parseIdentifier();
  while (cursor < source.size() && std::isspace(static_cast<unsigned char>(source[cursor])) != 0)
    ++cursor;
  if (name.empty() || cursor >= source.size() || (source[cursor] != ')' && source[cursor] != ','))
    return false;
  test = suite + "." + name;
  return true;
}

inline TestRelations test_relations_from_source(std::string_view source)
{
  TestRelations relations;
  std::istringstream input{std::string{source}};
  std::set<std::string> pendingRelations;
  std::string line;
  while (std::getline(input, line))
  {
    const size_t first = line.find_first_not_of(" \t\r");
    const std::string_view trimmed =
      first == std::string::npos ? std::string_view{} : std::string_view{line}.substr(first);
    if (trimmed.empty())
      continue;
    if (trimmed.starts_with("//"))
    {
      constexpr std::string_view relationPrefix =
        "@rela"
        "tion(";
      const size_t relation = trimmed.find(relationPrefix);
      if (relation != std::string_view::npos)
      {
        const size_t criterionBegin = relation + relationPrefix.size();
        const size_t criterionEnd = trimmed.find(',', criterionBegin);
        if (criterionEnd != std::string_view::npos &&
            trimmed.find("scope=function", criterionEnd) != std::string_view::npos)
          pendingRelations.insert(std::string{trimmed.substr(criterionBegin, criterionEnd - criterionBegin)});
      }
      continue;
    }

    if (!trimmed.starts_with("TEST"))
    {
      pendingRelations.clear();
      continue;
    }

    std::string macro{trimmed};
    std::string test;
    for (size_t continuation = 0; continuation < 8 && !parse_test_macro(macro, 0, test); ++continuation)
    {
      if (!std::getline(input, line))
        break;
      macro += '\n';
      macro += line;
    }
    if (!test.empty())
    {
      auto& testRelations = relations[test];
      testRelations.insert(pendingRelations.begin(), pendingRelations.end());
    }
    pendingRelations.clear();
  }
  return relations;
}

inline TestRelations declared_test_relations(const std::filesystem::path& repositoryRoot)
{
  TestRelations relations;
  for (const auto& entry : std::filesystem::recursive_directory_iterator{repositoryRoot / "tests"})
  {
    if (!entry.is_regular_file() || entry.path().extension() != ".cpp")
      continue;
    std::ifstream input{entry.path()};
    std::ostringstream buffer;
    buffer << input.rdbuf();
    const auto fromSource = test_relations_from_source(buffer.str());
    for (const auto& [test, criteria] : fromSource)
      relations[test].insert(criteria.begin(), criteria.end());
  }
  return relations;
}

inline std::vector<std::string> validate_inventory(
  const std::vector<std::string>& derived, const std::vector<Row>& rows)
{
  const std::set<std::string_view> allowed{
    propagatesResult, locallyGeneratedResult, fireAndForget, privateContinuation, outboundLifecycle};
  const std::set<std::string> expected{derived.begin(), derived.end()};
  std::set<std::string> seen;
  std::vector<std::string> errors;
  for (const auto& row : rows)
  {
    if (!seen.insert(row.identity).second)
      errors.push_back("duplicate:" + row.identity);
    if (!expected.contains(row.identity))
      errors.push_back("stale:" + row.identity);
    if (!allowed.contains(std::string_view{row.classification}))
      errors.push_back("classification:" + row.identity);
  }
  for (const auto& identity : expected)
  {
    if (!seen.contains(identity))
      errors.push_back("unclassified:" + identity);
  }
  std::sort(errors.begin(), errors.end());
  return errors;
}

inline std::vector<std::string> validate(const std::vector<std::string>& derived,
  const std::vector<Row>& rows, const std::set<std::string>& criteria, const TestRelations& testRelations)
{
  std::vector<std::string> errors = validate_inventory(derived, rows);
  for (const auto& row : rows)
  {
    if (row.classification == propagatesResult)
    {
      if (!criteria.contains(row.criterion))
        errors.push_back("criterion:" + row.identity);
      const auto test = testRelations.find(row.test);
      if (test == testRelations.end())
        errors.push_back("test:" + row.identity);
      else if (!test->second.contains(row.criterion))
        errors.push_back("relation:" + row.identity);
    }
    else if (!row.criterion.empty() || !row.test.empty())
      errors.push_back("nonpropagating-owner:" + row.identity);
  }
  std::sort(errors.begin(), errors.end());
  return errors;
}

}  // namespace ua::test_helpers::server_async_catalogue

#endif  // UASDK_TESTS_SERVER_ASYNC_SURFACE_CATALOGUE_H

// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "reporter.h"

#include "ua_json_helpers.h"

#include <boost/json.hpp>
#include <filesystem>
#include <fstream>
#include <iomanip>

namespace fuzz
{

Reporter::Reporter(const FuzzerConfig::Reporting& config, const ua::Logger& logger)
  : mConfig(config), mLogger(logger.with_category("reporter"))
{
  if (mConfig.file)
  {
    std::filesystem::create_directories(mConfig.outputDir);
    std::filesystem::create_directories(mConfig.outputDir + "/findings");
  }
}

void Reporter::report_finding(const Finding& finding)
{
  std::lock_guard lock(mMutex);

  auto f = finding;
  f.id = mNextFindingId++;
  f.timestamp = std::chrono::system_clock::now();

  if (mConfig.console)
  {
    print_finding_console(f);
  }

  if (mConfig.file)
  {
    write_finding_files(f);
  }

  mFindings.push_back(std::move(f));
}

void Reporter::update_status(
  uint64_t totalCases, double casesPerSec, FuzzLayer currentLayer, bool serverAlive)
{
  if (!mConfig.console)
    return;

  auto now = std::chrono::steady_clock::now();
  auto interval = std::chrono::milliseconds(1000 / std::max(mConfig.consoleUpdateHz, 1u));

  std::lock_guard lock(mMutex);

  if (now - mLastStatusUpdate < interval)
    return;
  mLastStatusUpdate = now;

  mLogger.info({{"cases", static_cast<int64_t>(totalCases)},
                 {"rate", static_cast<int64_t>(casesPerSec)},
                 {"findings", static_cast<int64_t>(mFindings.size())},
                 {"layer", std::string_view{to_string(currentLayer)}},
                 {"server", std::string_view{serverAlive ? "alive" : "dead"}}},
    "Status update");
}

void Reporter::write_summary(const FuzzResult& result)
{
  if (!mConfig.file)
    return;

  boost::json::object summary;
  summary["total_cases"] = result.totalCases;
  summary["elapsed_seconds"] = result.elapsedSeconds;
  summary["cases_per_second"] = result.casesPerSecond;
  summary["security_findings"] = result.securityFindings;
  summary["memory_leaks"] = result.memoryLeaks;
  summary["resource_leaks"] = result.resourceLeaks;
  summary["crashes"] = result.crashes;
  summary["critical_behaviour"] = result.criticalBehaviour;
  summary["perf_findings"] = result.perfFindings;
  summary["findings_dir"] = result.findingsDir;

  boost::json::array findingsArr;
  {
    std::lock_guard lock(mMutex);
    for (const auto& f : mFindings)
    {
      boost::json::object fo;
      fo["id"] = f.id;
      fo["class"] = to_string(f.findingClass);
      fo["severity"] = to_string(f.severity);
      fo["layer"] = to_string(f.layer);
      fo["service"] = to_string(f.service);
      fo["case_number"] = f.caseNumber;
      fo["description"] = f.description;
      findingsArr.push_back(std::move(fo));
    }
  }
  summary["findings"] = std::move(findingsArr);

  auto path = mConfig.outputDir + "/run_summary.json";
  std::ofstream out(path);
  out << ua::json_helpers::pretty_json(summary);
}

std::vector<Finding> Reporter::findings() const
{
  std::lock_guard lock(mMutex);
  return mFindings;
}

uint32_t Reporter::finding_count() const
{
  std::lock_guard lock(mMutex);
  return static_cast<uint32_t>(mFindings.size());
}

void Reporter::write_finding_files(const Finding& finding)
{
  auto base = mConfig.outputDir + "/findings/finding_" + std::to_string(finding.id);

  // Write raw trigger bytes.
  if (!finding.triggerBytes.empty())
  {
    std::ofstream binFile(base + ".bin", std::ios::binary);
    binFile.write(reinterpret_cast<const char*>(finding.triggerBytes.data()),
      static_cast<std::streamsize>(finding.triggerBytes.size()));
  }

  // Write metadata JSON.
  boost::json::object meta;
  meta["id"] = finding.id;
  meta["class"] = to_string(finding.findingClass);
  meta["severity"] = to_string(finding.severity);
  meta["layer"] = to_string(finding.layer);
  meta["service"] = to_string(finding.service);
  meta["strategy"] = to_string(finding.strategy);
  meta["case_number"] = finding.caseNumber;
  meta["description"] = finding.description;
  meta["latency_us"] = finding.latencyUs;
  meta["connection_dropped"] = finding.connectionDropped;
  meta["replay_cmd"] = "opcua-fuzzer --replay " + base + ".bin";

  std::ofstream metaFile(base + ".meta.json");
  metaFile << ua::json_helpers::pretty_json(meta);
}

void Reporter::print_finding_console(const Finding& finding)
{
  mLogger.warning({{"id", static_cast<int64_t>(finding.id)},
                    {"layer", std::string_view{to_string(finding.layer)}},
                    {"class", std::string_view{to_string(finding.findingClass)}},
                    {"service", std::string_view{to_string(finding.service)}},
                    {"severity", std::string_view{to_string(finding.severity)}}},
    "{}",
    finding.description);
}

}  // namespace fuzz

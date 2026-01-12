#pragma once

#include <Windows.h>

#include <vector>
#include <unordered_set>

#include "ConfigParser.h"

enum class CoreType
{
    Unknown,
    PCore,
    ECore
};

struct LogicalProcessor
{
    int group = 0;
    int number = 0;
    int globalIndex = 0;
};

struct PhysicalCore
{
    int physicalIndex = 0;
    CoreType type = CoreType::Unknown;
    std::vector<LogicalProcessor> logical;
};

struct OccupiedCorePolicy
{
    std::unordered_set<int> forbiddenPhysical;
    std::unordered_set<int> weakPhysical;
};

struct AutoAssignmentState
{
    std::unordered_set<int> usedLogical;
    std::unordered_set<int> usedPhysical;

    void Reset();
    void Reserve(int logicalIndex, int physicalIndex);
    bool IsLogicalUsed(int logicalIndex) const;
    bool IsPhysicalUsed(int physicalIndex) const;
};

class CpuTopology
{
public:
    bool Refresh();

    int GetPhysicalCoreCount() const { return static_cast<int>(cores_.size()); }
    const std::vector<PhysicalCore>& GetCores() const { return cores_; }
    const PhysicalCore* GetCore(int physicalIndex) const;
    CoreType GetCoreType(int physicalIndex) const;

private:
    std::vector<PhysicalCore> cores_;
};

struct AutoSelection
{
    bool valid = false;
    int physicalIndex = -1;
    int logicalIndex = -1;
    int group = 0;
    int groupNumber = 0;
};

AutoSelection SelectAutoCore(const CpuTopology& topology,
                             const OccupiedCorePolicy& policy,
                             AutoAssignmentState& state,
                             AutoCorePreference preference,
                             bool isMainThread);

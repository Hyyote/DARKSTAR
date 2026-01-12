#include "CPUTopology.h"

#include <vector>
#include <algorithm>

#include "Logger.h"

void AutoAssignmentState::Reset()
{
    usedLogical.clear();
    usedPhysical.clear();
}

void AutoAssignmentState::Reserve(int logicalIndex, int physicalIndex)
{
    usedLogical.insert(logicalIndex);
    usedPhysical.insert(physicalIndex);
}

bool AutoAssignmentState::IsLogicalUsed(int logicalIndex) const
{
    return usedLogical.find(logicalIndex) != usedLogical.end();
}

bool AutoAssignmentState::IsPhysicalUsed(int physicalIndex) const
{
    return usedPhysical.find(physicalIndex) != usedPhysical.end();
}

namespace
{
    CoreType ToCoreType(const PROCESSOR_RELATIONSHIP& relationship)
    {
        if (relationship.EfficiencyClass > 0)
        {
            return CoreType::ECore;
        }
        return CoreType::PCore;
    }
}

bool CpuTopology::Refresh()
{
    cores_.clear();

    DWORD length = 0;
    if (!GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &length))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            LOG_ERROR("GetLogicalProcessorInformationEx failed: %lu", GetLastError());
            return false;
        }
    }

    std::vector<BYTE> buffer(length);
    if (!GetLogicalProcessorInformationEx(RelationProcessorCore,
                                          reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(buffer.data()),
                                          &length))
    {
        LOG_ERROR("GetLogicalProcessorInformationEx failed on second call: %lu", GetLastError());
        return false;
    }

    auto current = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(buffer.data());
    int globalLogical = 0;

    while (reinterpret_cast<BYTE*>(current) < buffer.data() + length)
    {
        if (current->Relationship == RelationProcessorCore)
        {
            PROCESSOR_RELATIONSHIP& rel = current->Processor;
            PhysicalCore core;
            core.physicalIndex = static_cast<int>(cores_.size());
            core.type = ToCoreType(rel);

            KAFFINITY mask = rel.GroupMask[0].Mask;
            WORD group = rel.GroupMask[0].Group;
            for (DWORD bit = 0; bit < sizeof(KAFFINITY) * 8; ++bit)
            {
                if (mask & (static_cast<KAFFINITY>(1) << bit))
                {
                    LogicalProcessor logical;
                    logical.group = group;
                    logical.number = static_cast<int>(bit);
                    logical.globalIndex = globalLogical++;
                    core.logical.push_back(logical);
                }
            }

            if (core.logical.empty())
            {
                core.type = CoreType::Unknown;
            }

            cores_.push_back(core);
        }

        current = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(
            reinterpret_cast<BYTE*>(current) + current->Size);
    }

    return !cores_.empty();
}

const PhysicalCore* CpuTopology::GetCore(int physicalIndex) const
{
    if (physicalIndex < 0 || physicalIndex >= static_cast<int>(cores_.size()))
    {
        return nullptr;
    }
    return &cores_[physicalIndex];
}

CoreType CpuTopology::GetCoreType(int physicalIndex) const
{
    if (physicalIndex < 0 || physicalIndex >= static_cast<int>(cores_.size()))
    {
        return CoreType::Unknown;
    }
    return cores_[physicalIndex].type;
}

AutoSelection SelectAutoCore(const CpuTopology& topology,
                             const OccupiedCorePolicy& policy,
                             AutoAssignmentState& state,
                             AutoCorePreference preference,
                             bool isMainThread)
{
    AutoSelection selection;

    std::vector<const PhysicalCore*> candidates;
    candidates.reserve(topology.GetCores().size());

    for (const auto& core : topology.GetCores())
    {
        bool matchesPreference = false;
        if (preference == AutoCorePreference::Any)
        {
            matchesPreference = true;
        }
        else if (preference == AutoCorePreference::PCore && core.type != CoreType::ECore)
        {
            matchesPreference = true;
        }
        else if (preference == AutoCorePreference::ECore && core.type == CoreType::ECore)
        {
            matchesPreference = true;
        }

        if (matchesPreference)
        {
            candidates.push_back(&core);
        }
    }

    if (candidates.empty())
    {
        for (const auto& core : topology.GetCores())
        {
            candidates.push_back(&core);
        }
    }

    auto allowed = [&](int physical) {
        if (policy.forbiddenPhysical.find(physical) != policy.forbiddenPhysical.end())
        {
            return false;
        }
        return true;
    };

    for (const PhysicalCore* core : candidates)
    {
        if (!allowed(core->physicalIndex))
        {
            continue;
        }
        if (state.IsPhysicalUsed(core->physicalIndex) && !isMainThread)
        {
            continue;
        }

        for (const auto& logical : core->logical)
        {
            if (state.IsLogicalUsed(logical.globalIndex))
            {
                continue;
            }

            selection.valid = true;
            selection.physicalIndex = core->physicalIndex;
            selection.logicalIndex = logical.globalIndex;
            selection.group = logical.group;
            selection.groupNumber = logical.number;
            state.Reserve(logical.globalIndex, core->physicalIndex);
            return selection;
        }
    }

    for (const PhysicalCore* core : candidates)
    {
        if (!allowed(core->physicalIndex))
        {
            continue;
        }

        for (const auto& logical : core->logical)
        {
            if (state.IsLogicalUsed(logical.globalIndex))
            {
                continue;
            }

            selection.valid = true;
            selection.physicalIndex = core->physicalIndex;
            selection.logicalIndex = logical.globalIndex;
            selection.group = logical.group;
            selection.groupNumber = logical.number;
            state.Reserve(logical.globalIndex, core->physicalIndex);
            return selection;
        }
    }

    return selection;
}

/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "rdb_hooks.h"

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>
#include <sys/statfs.h>

#include "ans_log_wrapper.h"
#include "directory_ex.h"
#include "event_report.h"
#include "notification_constant.h"

namespace OHOS::Notification::Domain {
namespace {
static int32_t USER_DATA_SIZE_REPORT_INTERVAL = 24 * NotificationConstant::HOUR_TO_MS;
static int64_t lastReportTime_ = 0;
const std::string ANS_COMPONENT_NAME = "distributed_notification_service";
const std::string ANS_PARTITION_NAME = "/data";
const std::vector<std::string> ANS_FOLDER_PATHS = {
    "/data/service/el1/public/database/notification_service"
};
}
std::vector<std::uint64_t> GetFileOrFolderSize(const std::vector<std::string> &paths)
{
    std::vector<std::uint64_t> folderSize;
    for (auto path : paths) {
        folderSize.emplace_back(OHOS::GetFolderSize(path));
    }
    return folderSize;
}

std::uint64_t GetRemainPartitionSize(const std::string &partitionName)
{
    struct statfs stat;
    if (statfs(partitionName.c_str(), &stat) != 0) {
        return -1;
    }
    std::uint64_t blockSize = stat.f_bsize;
    std::uint64_t freeSize = stat.f_bfree * blockSize;
    constexpr double units = 1024.0;
    return freeSize / (units * units);
}

void OnSendUserDataSizeHisysevent()
{
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    if (lastReportTime_ != 0 && abs(now - lastReportTime_) <= USER_DATA_SIZE_REPORT_INTERVAL) {
        ANS_LOGD("no need report");
        return;
    }

    ANS_LOGI("user data size hisysevent report");
    lastReportTime_ = now;

    UserDataSizeInfo userDataSizeInfo;
    userDataSizeInfo.componentName = ANS_COMPONENT_NAME;
    userDataSizeInfo.partitionName = ANS_PARTITION_NAME;
    userDataSizeInfo.folderPath = ANS_FOLDER_PATHS;
    userDataSizeInfo.folderSize = GetFileOrFolderSize(ANS_FOLDER_PATHS);
    userDataSizeInfo.remainPartitionSize = GetRemainPartitionSize(ANS_PARTITION_NAME);

    EventReport::SendHiSysEvent(userDataSizeInfo);
}
}
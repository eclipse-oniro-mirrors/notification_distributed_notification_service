/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "mock_reminder_bundle_manager_helper.h"

#include "reminder_bundle_manager_helper.h"

namespace OHOS::Notification {
namespace {
bool g_mockGetBundleInfoRet = false;
int32_t g_mockGetDefaultUidByBundleNameRet = 0;
std::string g_mockGetBundleNameByUidRet;
AppExecFwk::BundleInfo g_mockBundleInfo;
}

void MockReminderBundleManagerHelper::MockGetBundleNameByUid(const std::string& ret)
{
    g_mockGetBundleNameByUidRet = ret;
}

void MockReminderBundleManagerHelper::MockGetDefaultUidByBundleName(const int32_t ret)
{
    g_mockGetDefaultUidByBundleNameRet = ret;
}

void MockReminderBundleManagerHelper::MockGetBundleInfo(const bool ret, const AppExecFwk::BundleInfo& bundleInfo)
{
    g_mockBundleInfo = bundleInfo;
    g_mockGetBundleInfoRet = ret;
}

ReminderBundleManagerHelper::ReminderBundleManagerHelper()
{}

ReminderBundleManagerHelper::~ReminderBundleManagerHelper()
{}

std::string ReminderBundleManagerHelper::GetBundleNameByUid(int32_t uid)
{
    return g_mockGetBundleNameByUidRet;
}

int32_t ReminderBundleManagerHelper::GetDefaultUidByBundleName(const std::string& bundle, const int32_t userId)
{
    return g_mockGetDefaultUidByBundleNameRet;
}

bool ReminderBundleManagerHelper::GetBundleInfo(const std::string& bundleName, const AppExecFwk::BundleFlag flag,
    const int32_t userId, AppExecFwk::BundleInfo& bundleInfo)
{
    bundleInfo = g_mockBundleInfo;
    return g_mockGetBundleInfoRet;
}
} // namespace OHOS
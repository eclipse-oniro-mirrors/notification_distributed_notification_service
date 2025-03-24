/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "mock_bundle_mgr.h"

#include <functional>
#include <gtest/gtest.h>
#include "ans_ut_constant.h"

namespace OHOS {
namespace Notification {
namespace {
bool g_isNonBundleName = false;
bool g_isEnable = true;
bool g_setBundleInfoEnabled = false;
}

void MockSetBundleInfoEnabled(bool enabled)
{
    g_setBundleInfoEnabled = enabled;
}

void MockIsNonBundleName(bool isNonBundleName)
{
    g_isNonBundleName = isNonBundleName;
}

void MockDistributedNotificationEnabled(bool isEnable)
{
    g_isEnable = isEnable;
}
}
}

namespace OHOS {
namespace AppExecFwk {
ErrCode BundleMgrProxy::GetNameForUid(const int uid, std::string &name)
{
    name = Notification::g_isNonBundleName ? "": "bundleName";
    return ERR_OK;
}

bool BundleMgrProxy::GetBundleInfo(const std::string &bundleName, const BundleFlag flag, BundleInfo &bundleInfo,
    int32_t userId)
{
    if (Notification::g_setBundleInfoEnabled) {
        bundleInfo.applicationInfo.allowEnableNotification = true;
    }
    return true;
}

int BundleMgrProxy::GetUidByBundleName(const std::string &bundleName, const int userId)
{
    if (userId == 0) {
        return -1;
    } else {
        return Notification::NON_SYSTEM_APP_UID;
    }
}

bool BundleMgrProxy::GetApplicationInfo(
    const std::string &appName, const ApplicationFlag flag, const int userId, ApplicationInfo &appInfo)
{
    appInfo.distributedNotificationEnabled = Notification::g_isEnable;
    return true;
}

} // namespace AppExecFwk
} // namespace OHOS

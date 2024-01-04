/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "mock_bundle_manager.h"

#include <gtest/gtest.h>
#include "ability_info.h"
#include "application_info.h"

namespace OHOS {
namespace Notification {
namespace {
bool g_isNonBundleName = false;
int32_t NON_SYSTEM_APP_UID = 1000;
}

void MockIsNonBundleName(bool isNonBundleName)
{
    g_isNonBundleName = isNonBundleName;
}
}
}

namespace OHOS {
namespace AppExecFwk {
constexpr int SYSTEM_APP_UUID = 1000;

void MockBundleManager::MockSetIsSystemApp(bool isSystemApp)
{
    isSystemAppMock_ = true;
    isSystemApp_ = isSystemApp;
}

bool MockBundleManager::CheckIsSystemAppByUid(const int uid)
{
    if (isSystemAppMock_) {
        return isSystemApp_;
    }
    return (uid < SYSTEM_APP_UUID) ? false : true;
}

ErrCode BundleMgrProxy::GetNameForUid(const int uid, std::string &name)
{
    GTEST_LOG_(INFO) << "mock GetNameForUid.";
    name = Notification::g_isNonBundleName ? "": "bundleName";
    return ERR_OK;
}

bool BundleMgrProxy::GetBundleInfo(const std::string &bundleName, const BundleFlag flag, BundleInfo &bundleInfo,
    int32_t userId)
{
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
    appInfo.distributedNotificationEnabled = true;
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS

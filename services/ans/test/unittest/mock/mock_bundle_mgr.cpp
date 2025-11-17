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
#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {
namespace {
bool g_isNonBundleName = false;
bool g_isEnable = true;
bool g_setBundleInfoEnabled = false;
bool g_getBundleInfoFailed = false;
bool g_isNeedHapModuleInfos = false;
bool g_isMockQueryExtensionAbilityInfos = false;
bool g_isMockGetCloneAppIndexes = false;
bool g_isMockGetCloneBundleInfo = false;
constexpr const int32_t MOCK_UID = 20020010;
}

void MockSetBundleInfoFailed(bool getFail)
{
    g_getBundleInfoFailed = getFail;
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

void MockIsNeedHapModuleInfos(bool isNeed)
{
    g_isNeedHapModuleInfos = isNeed;
}

void MockQueryExtensionAbilityInfos(bool enabled)
{
    g_isMockQueryExtensionAbilityInfos = enabled;
}

void MockGetCloneAppIndexes(bool enabled)
{
    g_isMockGetCloneAppIndexes = enabled;
}

void MockGetCloneBundleInfo(bool enabled)
{
    g_isMockGetCloneBundleInfo = enabled;
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
    if (Notification::g_getBundleInfoFailed) {
        return false;
    }
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

bool BundleMgrProxy::GetBundleInfos(const BundleFlag  flags, std::vector<BundleInfo> &bundleInfos, int32_t userId)
{
    if (Notification::g_setBundleInfoEnabled) {
        int i = 1;
        BundleInfo info;
        info.applicationInfo.allowEnableNotification = true;
        info.applicationInfo.bundleName = "test";
        info.uid = i;
        bundleInfos.push_back(info);
        BundleInfo info1;
        info1.applicationInfo.allowEnableNotification = false;
        info1.applicationInfo.bundleName = "test1";
        info1.uid = i+1;
        bundleInfos.push_back(info);
        return true;
    }
    return false;
}

ErrCode BundleMgrProxy::GetBundleInfoV9(
    const std::string& bundleName, int32_t flags, BundleInfo& bundleInfo, int32_t userId)
{
    if (Notification::g_getBundleInfoFailed) {
        return -1;
    }
    if (Notification::g_isNeedHapModuleInfos) {
        HapModuleInfo hapModuleInfo;
        ExtensionAbilityInfo extensionInfo;
        extensionInfo.type = AppExecFwk::ExtensionAbilityType::NOTIFICATION_SUBSCRIBER;
        extensionInfo.bundleName = "test_bundle";
        hapModuleInfo.extensionInfos.push_back(extensionInfo);
        bundleInfo.hapModuleInfos.push_back(hapModuleInfo);
    }
    return ERR_OK;
}

bool BundleMgrProxy::QueryExtensionAbilityInfos(const ExtensionAbilityType &extensionType, const int32_t &userId,
    std::vector<ExtensionAbilityInfo> &extensionInfos)
{
    if (Notification::g_isMockQueryExtensionAbilityInfos) {
        ExtensionAbilityInfo extensionInfo;
        extensionInfo.type = AppExecFwk::ExtensionAbilityType::NOTIFICATION_SUBSCRIBER;
        extensionInfo.bundleName = "test_bundle";
        extensionInfos.push_back(extensionInfo);
    }

    return true;
}

ErrCode BundleMgrProxy::GetCloneAppIndexes(const std::string &bundleName, std::vector<int32_t> &appIndexes,
    int32_t userId)
{
    if (Notification::g_isMockGetCloneAppIndexes) {
        appIndexes.push_back(1);
        return ERR_OK;
    }
    return -1;
}

ErrCode BundleMgrProxy::GetCloneBundleInfo(const std::string &bundleName, int32_t flag, int32_t appIndex,
    BundleInfo &bundleInfo, int32_t userId)
{
    if (Notification::g_isMockGetCloneBundleInfo) {
        bundleInfo.uid = Notification::MOCK_UID;
        return ERR_OK;
    }

    return -1;
}
} // namespace AppExecFwk
} // namespace OHOS

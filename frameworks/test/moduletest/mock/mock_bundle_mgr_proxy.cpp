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

#include "bundle_mgr_proxy.h"

#include "ipc_types.h"
#include "parcel.h"
#include "string_ex.h"

#include "appexecfwk_errors.h"
#include "bundle_constants.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
bool distributedNotificationEnabled = true;
}
void MockSetDistributedNotificationEnabled(bool enable)
{
    distributedNotificationEnabled = enable;
}

BundleMgrProxy::BundleMgrProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IBundleMgr>(impl)
{}

BundleMgrProxy::~BundleMgrProxy()
{}

bool BundleMgrProxy::GetBundleInfo(
    const std::string &bundleName, const BundleFlag flag, BundleInfo &bundleInfo, int32_t userId)
{
    bundleInfo.uid = 1;
    return true;
}

std::string BundleMgrProxy::GetAppIdByBundleName(const std::string &bundleName, const int userId)
{
    return "appId";
}

bool BundleMgrProxy::GetBundleNameForUid(const int uid, std::string &bundleName)
{
    bundleName = "bundleName";
    return true;
}

std::string BundleMgrProxy::GetAppType(const std::string &bundleName)
{
    return "Constants::EMPTY_STRING";
}
}  // namespace AppExecFwk
}  // namespace OHOS

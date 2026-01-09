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

#ifndef INFRASTRUCTURE_TEST_UNITTEST_MOCK_INCLUDE_MOCK_BUNDLE_MANAGER_H
#define INFRASTRUCTURE_TEST_UNITTEST_MOCK_INCLUDE_MOCK_BUNDLE_MANAGER_H

#include "gmock/gmock.h"
#include "bundle_info.h"
#include "iremote_proxy.h"
#include "bundle_mgr_interface.h"

namespace OHOS {
namespace Notification {
namespace Infra {
class MockBundleMgr : public AppExecFwk::IBundleMgr {
public:
    MOCK_METHOD(sptr<IRemoteObject>, AsObject, (), (override));
    MOCK_METHOD(bool, CheckIsSystemAppByUid, (int32_t uid), (override));
    MOCK_METHOD(ErrCode, GetNameForUid, (const int uid, std::string &name), (override));
    MOCK_METHOD(int32_t, GetUidByBundleName, (const std::string &bundleName, const int32_t userId), (override));
    MOCK_METHOD(int32_t, GetUidByBundleName, (const std::string &bundleName,
        const int32_t userId, int32_t appIndex), (override));
    MOCK_METHOD(ErrCode, GetNameAndIndexForUid,
        (const int32_t uid, std::string &bundleName, int32_t &appIndex), (override));
    MOCK_METHOD(bool, GetBundleInfo,
        (const std::string &bundleName, const AppExecFwk::BundleFlag flag,
        AppExecFwk::BundleInfo &bundleInfo, int32_t userId), (override));
    MOCK_METHOD(bool, GetBundleInfos,
        (const AppExecFwk::BundleFlag flags, std::vector<AppExecFwk::BundleInfo> &bundleInfos, int32_t userId), (override));
    MOCK_METHOD(ErrCode, GetBundleInfoV9,
        (const std::string &bundleName, int32_t flags, AppExecFwk::BundleInfo &bundleInfo, int32_t userId), (override));
    MOCK_METHOD(ErrCode, GetBundleInfosV9,
        (int32_t flags, std::vector<AppExecFwk::BundleInfo> &bundleInfos, int32_t userId), (override));
    MOCK_METHOD(ErrCode, GetCloneAppIndexes,
        (const std::string &bundleName, std::vector<int32_t> &appIndexes, int32_t userId), (override));
    MOCK_METHOD(ErrCode, GetCloneBundleInfo,
        (const std::string &bundleName, int32_t flag, int32_t appIndex,
        AppExecFwk::BundleInfo &bundleInfo, int32_t userId), (override));
};

}  // namespace Infra
}  // namespace Notification
}  // namespace OHOS

#endif  // INFRASTRUCTURE_TEST_UNITTEST_MOCK_INCLUDE_MOCK_BUNDLE_MANAGER_H

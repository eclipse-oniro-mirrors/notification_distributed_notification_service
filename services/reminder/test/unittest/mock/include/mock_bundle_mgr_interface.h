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

#ifndef BASE_NOTIFICATION_REMINDER_MOCK_BUNDLE_MGR_INTERFACE_H
#define BASE_NOTIFICATION_REMINDER_MOCK_BUNDLE_MGR_INTERFACE_H

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "bundle_mgr_interface.h"
#include "app_control_interface.h"
#include "iremote_object.h"
#include "iremote_broker.h"

namespace OHOS::Notification {
class MockIBundleMgr : public AppExecFwk::IBundleMgr {
public:
    MOCK_METHOD(sptr<IRemoteObject>, AsObject, (), (override));

    MOCK_METHOD(ErrCode, GetNameForUid,
        (const int, std::string&),
        (override));

    MOCK_METHOD(int, GetUidByBundleName,
        (const std::string&, const int),
        (override));

    MOCK_METHOD(bool, GetBundleInfo,
        (const std::string&, const AppExecFwk::BundleFlag, AppExecFwk::BundleInfo&, int32_t),
        (override));

    MOCK_METHOD(ErrCode, GetNameAndIndexForUid,
        (const int32_t, std::string&, int32_t&),
        (override));

    MOCK_METHOD(sptr<AppExecFwk::IAppControlMgr>, GetAppControlProxy, (), (override));
};

class MockIAppControlMgr : public AppExecFwk::IAppControlMgr {
public:
    MOCK_METHOD(sptr<IRemoteObject>, AsObject, (), (override));

    MOCK_METHOD(ErrCode, GetAbilityRunningControlRule,
        (const std::string&, int32_t, std::vector<AppExecFwk::DisposedRule>&, int32_t),
        (override));
};
}
#endif // BASE_NOTIFICATION_REMINDER_MOCK_BUNDLE_MGR_INTERFACE_H
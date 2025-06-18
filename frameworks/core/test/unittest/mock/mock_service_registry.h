/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
 
#ifndef OHOS_NOTIFICATION_MOCK_SYSTEM_ABILITY_MANAGER_H
#define OHOS_NOTIFICATION_MOCK_SYSTEM_ABILITY_MANAGER_H
 
#include "gmock/gmock.h"
 
#include "iremote_object.h"
#include "iremote_stub.h"
 
namespace OHOS {
namespace Notification {
class MockSystemAbilityManager : public IRemoteStub<ISystemAbilityManager> {
public:
    MockSystemAbilityManager() {};
    virtual ~MockSystemAbilityManager() {};
 
    MOCK_METHOD1(ListSystemAbilities, std::vector<std::u16string>(unsigned int));
    MOCK_METHOD1(GetSystemAbility, sptr<IRemoteObject>(int32_t));
    MOCK_METHOD2(GetSystemAbility, sptr<IRemoteObject>(int32_t, const std::string &));
    MOCK_METHOD1(CheckSystemAbility, sptr<IRemoteObject>(int32_t));
    MOCK_METHOD2(CheckSystemAbility, sptr<IRemoteObject>(int32_t, const std::string &));
    MOCK_METHOD2(CheckSystemAbility, sptr<IRemoteObject>(int32_t, bool &));
    MOCK_METHOD1(RemoveSystemAbility, int32_t(int32_t));
    MOCK_METHOD2(UnSubscribeSystemAbility, int32_t(int32_t, const sptr<ISystemAbilityStatusChange> &));
    MOCK_METHOD2(AddOnDemandSystemAbilityInfo, int32_t(int32_t, const std::u16string &));
    MOCK_METHOD3(AddSystemAbility, int32_t(int32_t, const sptr<IRemoteObject> &, const SAExtraProp &));
    MOCK_METHOD2(AddSystemProcess, int32_t(const std::u16string &, const sptr<IRemoteObject> &));
    MOCK_METHOD2(LoadSystemAbility, sptr<IRemoteObject>(int32_t, int32_t));
    MOCK_METHOD2(LoadSystemAbility, int32_t(int32_t, const sptr<ISystemAbilityLoadCallback> &));
    MOCK_METHOD3(LoadSystemAbility, int32_t(int32_t, const std::string &, const sptr<ISystemAbilityLoadCallback> &));
    MOCK_METHOD1(UnloadSystemAbility, int32_t(int32_t));
    MOCK_METHOD1(CancelUnloadSystemAbility, int32_t(int32_t));
    MOCK_METHOD1(GetRunningSystemProcess, int32_t(std::list<SystemProcessInfo> &));
    MOCK_METHOD1(SubscribeSystemProcess, int32_t(const sptr<ISystemProcessStatusChange> &));
    MOCK_METHOD4(SendStrategy, int32_t(int32_t, std::vector<int32_t> &, int32_t, std::string &));
    MOCK_METHOD1(UnSubscribeSystemProcess, int32_t(const sptr<ISystemProcessStatusChange> &));
    MOCK_METHOD2(GetOnDemandReasonExtraData, int32_t(int64_t, MessageParcel &));
    MOCK_METHOD2(GetSystemProcessInfo, int32_t(int32_t, SystemProcessInfo &));
    MOCK_METHOD3(GetOnDemandPolicy, int32_t(int32_t, OnDemandPolicyType, std::vector<SystemAbilityOnDemandEvent> &));
    MOCK_METHOD3(
        UpdateOnDemandPolicy, int32_t(int32_t, OnDemandPolicyType, const std::vector<SystemAbilityOnDemandEvent> &));
    MOCK_METHOD1(GetOnDemandSystemAbilityIds, int32_t(std::vector<int32_t> &));
    MOCK_METHOD0(UnloadAllIdleSystemAbility, int32_t());
    MOCK_METHOD2(GetExtensionSaIds, int32_t(const std::string&, std::vector<int32_t> &));
    MOCK_METHOD2(GetExtensionRunningSaList, int32_t(const std::string&, std::vector<sptr<IRemoteObject>>&));
    MOCK_METHOD2(GetRunningSaExtensionInfoList, int32_t(const std::string&, std::vector<SaExtensionInfo>&));
    MOCK_METHOD3(GetCommonEventExtraDataIdlist, int32_t(int32_t, std::vector<int64_t>&, const std::string&));
 
    int32_t SubscribeSystemAbility(int32_t systemAbilityId, const sptr<ISystemAbilityStatusChange>& listener) override
    {
        std::cout << "SubscribeSystemAbility" << std::endl;
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
};
} // namespace Notification
} // namespace OHOS
#endif // OHOS_NOTIFICATION_MOCK_SYSTEM_ABILITY_MANAGER_H
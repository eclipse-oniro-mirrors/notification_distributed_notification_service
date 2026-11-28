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

#include "mock_mst_samgr.h"

#include <string>

#include "errors.h"
#include "ipc_skeleton.h"
#include "system_ability_definition.h"

using namespace testing;

namespace OHOS {
namespace Notification {
namespace {
class MstSystemAbilityManager : public testing::NiceMock<MockSystemAbilityManager> {
public:
    int32_t SubscribeSystemAbility(int32_t, const sptr<ISystemAbilityStatusChange> &) override
    {
        return ERR_OK;
    }
};
} // namespace

sptr<MockSystemAbilityManager> GetMstSystemAbilityManager()
{
    static sptr<MockSystemAbilityManager> instance = new (std::nothrow) MstSystemAbilityManager();
    return instance;
}

sptr<ISystemAbilityManager> GetMstRealSystemAbilityManager()
{
    return iface_cast<ISystemAbilityManager>(IPCSkeleton::GetContextObject());
}

void ConfigureMstSamgr(const sptr<ISystemAbilityManager> &realSamgr)
{
    auto mock = GetMstSystemAbilityManager();
    ON_CALL(*mock, GetSystemAbility(_))
        .WillByDefault(Invoke([realSamgr](int32_t systemAbilityId) {
            return realSamgr->GetSystemAbility(
                systemAbilityId == ADVANCED_NOTIFICATION_SERVICE_ABILITY_ID ? MST_ANS_SA_ID : systemAbilityId);
        }));
    ON_CALL(*mock, GetSystemAbility(_, _))
        .WillByDefault(Invoke([realSamgr](int32_t systemAbilityId, const std::string &deviceId) {
            return realSamgr->GetSystemAbility(
                systemAbilityId == ADVANCED_NOTIFICATION_SERVICE_ABILITY_ID ? MST_ANS_SA_ID : systemAbilityId,
                deviceId);
        }));
    ON_CALL(*mock, CheckSystemAbility(_))
        .WillByDefault(Invoke([realSamgr](int32_t systemAbilityId) {
            return realSamgr->CheckSystemAbility(
                systemAbilityId == ADVANCED_NOTIFICATION_SERVICE_ABILITY_ID ? MST_ANS_SA_ID : systemAbilityId);
        }));
    testing::Mock::AllowLeak(mock.GetRefPtr());
}
} // namespace Notification

// The moduletest must not register the production ANS SA id in the device samgr: that replaces the
// real 3203 registration and samgr removes it when the test process exits. Override the samgr
// lookup instead (libans_innerkits references this symbol from libsamgr_proxy, which is not built
// with -Bsymbolic) so the SDK in the test process talks to a test-owned SA.
sptr<ISystemAbilityManager> SystemAbilityManagerClient::GetSystemAbilityManager()
{
    return Notification::GetMstSystemAbilityManager();
}
} // namespace OHOS

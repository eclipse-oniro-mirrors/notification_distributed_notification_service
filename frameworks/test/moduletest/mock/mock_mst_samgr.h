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

#ifndef OHOS_NOTIFICATION_MOCK_MST_SAMGR_H
#define OHOS_NOTIFICATION_MOCK_MST_SAMGR_H

#include "iservice_registry.h"
#include "mock_service_registry.h"

namespace OHOS {
namespace Notification {
// Test-owned SA id used by moduletests so they never register the production ANS SA id.
constexpr int32_t MST_ANS_SA_ID = 13203;

sptr<MockSystemAbilityManager> GetMstSystemAbilityManager();

// Real samgr obtained from the binder context manager, independent of the override above.
sptr<ISystemAbilityManager> GetMstRealSystemAbilityManager();

// Delegate every samgr lookup to the real manager; only the production ANS id is redirected to the
// test-owned SA. Must be called after the test SA was registered.
void ConfigureMstSamgr(const sptr<ISystemAbilityManager> &realSamgr);
} // namespace Notification
} // namespace OHOS
#endif // OHOS_NOTIFICATION_MOCK_MST_SAMGR_H

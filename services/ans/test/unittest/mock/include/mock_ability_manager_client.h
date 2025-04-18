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
#ifndef MOCK_OHOS_ABILITY_RUNTIME_MOCK_ABILITY_MANAGER_CLIENT_H
#define MOCK_OHOS_ABILITY_RUNTIME_MOCK_ABILITY_MANAGER_CLIENT_H

#include "iremote_object.h"
#include "iremote_stub.h"
#include "ability_connect_callback_interface.h"
#include "ability_manager_errors.h"
#include "ability_scheduler_interface.h"
#include "ability_manager_interface.h"
#define private public
#define protected public
#include "ability_manager_client.h"
#undef private
#undef protected
#include "ability_context.h"
#include "want.h"

namespace OHOS {
namespace AAFwk {
class MockAbilityManagerClient : public AbilityManagerClient {
public:
    MockAbilityManagerClient() = default;
    virtual ~MockAbilityManagerClient() = default;
    static std::shared_ptr<MockAbilityManagerClient> mockinstance_;
    static std::shared_ptr<MockAbilityManagerClient> GetInstance();
};
}  // namespace AAFwk
}  // namespace OHOS

#endif /* MOCK_OHOS_ABILITY_RUNTIME_MOCK_ABILITY_MANAGER_CLIENT_H */
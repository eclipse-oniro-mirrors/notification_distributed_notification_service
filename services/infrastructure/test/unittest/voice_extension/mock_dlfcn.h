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

#ifndef INFRASTRUCTURE_TEST_UNITTEST_VOICE_EXTENSION_MOCK_DLFCN_H
#define INFRASTRUCTURE_TEST_UNITTEST_VOICE_EXTENSION_MOCK_DLFCN_H

#include <cstdint>
#include <map>
#include <string>

#include "notification_request.h"

namespace OHOS::Notification::Infra::Test {

struct MockDlfcnState {
    bool dlopenSuccess = false;
    std::map<std::string, bool> dlsymSuccessMap;
    int32_t generateResult = 0;
    int32_t updateResult = 0;
    int32_t notifyResult = 0;
    std::string lastUpdateConfig;
    std::string lastNotifyEvent;
    bool dlcloseCalled = false;
};

extern MockDlfcnState g_mockDlfcn;

void ResetMockDlfcn();

}  // namespace Test
}  // namespace Infra
}  // namespace Notification
}  // namespace OHOS

#endif  // INFRASTRUCTURE_TEST_UNITTEST_VOICE_EXTENSION_MOCK_DLFCN_H
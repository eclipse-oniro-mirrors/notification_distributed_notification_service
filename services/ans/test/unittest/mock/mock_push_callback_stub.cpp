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

#include "mock_push_callback_stub.h"

namespace OHOS {
namespace Notification {
namespace {
int32_t g_retOnCheckNotification = 0;
}

void MockOnCheckNotification(const int32_t retOnCheckNotification)
{
    g_retOnCheckNotification = retOnCheckNotification;
}

} // namespace Notification
MockPushCallBackStub::MockPushCallBackStub() {}
MockPushCallBackStub::~MockPushCallBackStub() {}
int32_t MockPushCallBackStub::OnCheckNotification(const std::string &notificationData,
    const std::shared_ptr<Notification::PushCallBackParam> &pushCallBackParam)
{
    return Notification::g_retOnCheckNotification;
}
} // namespace OHOS

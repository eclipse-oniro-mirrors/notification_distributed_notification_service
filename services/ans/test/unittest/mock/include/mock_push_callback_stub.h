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

#ifndef ANS_MOCK_PUSH_CALL_BACK_STUB_H
#define ANS_MOCK_PUSH_CALL_BACK_STUB_H

#include <iremote_object.h>
#include <iremote_stub.h>

#include "push_callback_interface.h"

namespace OHOS {
class MockPushCallBackStub : public IRemoteStub<Notification::IPushCallBack> {
public:
    MockPushCallBackStub();
    virtual ~MockPushCallBackStub();
    virtual int32_t OnCheckNotification(const std::string &notificationData,
        const std::shared_ptr<Notification::PushCallBackParam> &pushCallBackParam) override;
    virtual int32_t OnCheckLiveView(const std::string& requestId,
        const std::vector<std::string>& bundles) override;
};
namespace Notification {
void MockOnCheckLiveView(const int32_t retOnCheckLiveView);
void MockOnCheckNotification(const int32_t retOnCheckNotification);
} // namespace Notification
}  // namespace OHOS
#endif  // ANS_MOCK_PUSH_CALL_BACK_STUB_H

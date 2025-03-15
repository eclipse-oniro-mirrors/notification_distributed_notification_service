/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#ifndef ANS_MOCK_SWING_CALL_BACK_STUB_H
#define ANS_MOCK_SWING_CALL_BACK_STUB_H
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED

#include <iremote_object.h>
#include <iremote_stub.h>

#include "iswing_call_back.h"

namespace OHOS {
class MockSwingCallBackStub : public IRemoteStub<Notification::ISwingCallBack> {
public:
    MockSwingCallBackStub();
    virtual ~MockSwingCallBackStub();
    virtual ErrCode OnUpdateStatus(bool isEnable, int32_t triggerMode, int32_t& funcResult) override;
};
}  // namespace OHOS
#endif  // ANS_MOCK_SWING_CALL_BACK_STUB_H
#endif

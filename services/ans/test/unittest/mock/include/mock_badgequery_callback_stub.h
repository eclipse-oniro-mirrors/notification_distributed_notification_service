/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef ANS_MOCK_BADGEQUERY_CALL_BACK_STUB_H
#define ANS_MOCK_BADGEQUERY_CALL_BACK_STUB_H

#include <iremote_object.h>
#include <iremote_stub.h>

#include "ibadge_query_callback.h"

namespace OHOS {
class MockBadgeQueryCallBackStub : public IRemoteStub<Notification::IBadgeQueryCallback> {
public:
    MockBadgeQueryCallBackStub();
    virtual ~MockBadgeQueryCallBackStub();
    virtual ErrCode OnBadgeNumberQuery(const sptr<NotificationBundleOption>& bundleOption,
        int32_t& badgeNumber) override;
};
}  // namespace OHOS
#endif  // ANS_MOCK_BADGEQUERY_CALL_BACK_STUB_H

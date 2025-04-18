/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#ifndef OHOS_NOTIFICATION_ENABLE_H
#define OHOS_NOTIFICATION_ENABLE_H

#include "notification_bundle_option.h"
#include "iremote_object.h"
#include "ans_dialog_host_client.h"

namespace OHOS {
namespace CJSystemapi {
constexpr int32_t SUBSCRIBE_USER_INIT = -1;

struct IsEnableParams {
    ::OHOS::Notification::NotificationBundleOption option;
    bool hasBundleOption = false;
    int32_t userId = SUBSCRIBE_USER_INIT;
    bool hasUserId = false;
    bool allowToPop = false;
    sptr<IRemoteObject> callerToken = nullptr;
    bool hasCallerToken = false;
};
} // namespace CJSystemapi
} // namespace OHOS

#endif // OHOS_NOTIFICATION_ENABLE_H
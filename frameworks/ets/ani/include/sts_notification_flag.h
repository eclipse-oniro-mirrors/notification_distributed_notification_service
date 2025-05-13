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

#ifndef OHOS_DISTRIBUTED_NOTIFICATION_SERVER_STS_NOTIFICATION_FLAG_H
#define OHOS_DISTRIBUTED_NOTIFICATION_SERVER_STS_NOTIFICATION_FLAG_H
#include "ani.h"
#include "notification_flags.h"

namespace OHOS {
namespace NotificationSts {
bool WarpNotificationFlags(ani_env* env, const std::shared_ptr<Notification::NotificationFlags> &flags,
    ani_object &flagsObject);
} // namespace NotificationSts
} // OHOS
#endif
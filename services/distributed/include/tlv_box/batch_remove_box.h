/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_BATCH_REMOVE_NOTIFICATION_BOX_H
#define BASE_NOTIFICATION_DISTRIBUTED_BATCH_REMOVE_NOTIFICATION_BOX_H

#include <string>

#include "box_base.h"
#include "tlv_box.h"

namespace OHOS {
namespace Notification {
class BatchRemoveNotificationBox : public BoxBase {
public:
    BatchRemoveNotificationBox();
    ~BatchRemoveNotificationBox();
    BatchRemoveNotificationBox(std::shared_ptr<TlvBox> box);
    bool SetNotificationHashCode(const std::string& hashCode);
};
}  // namespace Notification
}  // namespace OHOS
#endif // BASE_NOTIFICATION_DISTRIBUTED_BATCH_REMOVE_NOTIFICATION_BOX_H

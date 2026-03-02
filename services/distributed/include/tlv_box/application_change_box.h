/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_APPLICATION_BOX_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_APPLICATION_BOX_H

#include <string>
#include "tlv_box.h"
#include "box_base.h"
#include "notification_distributed_bundle.h"

namespace OHOS {
namespace Notification {

class ApplicationChangeBox : public BoxBase {
public:
    const static int32_t MAX_LIST_NUM = 20;

    ApplicationChangeBox();
    ApplicationChangeBox(std::shared_ptr<TlvBox> box);
    bool SetLocalDeviceId(const std::string &deviceId);
    bool SetApplicationSyncType(int32_t type);
    bool SetDataLength(int32_t length);
    bool SetApplicationChangeList(const std::vector<NotificationDistributedBundle>& applicationList);

    bool GetLocalDeviceId(std::string &deviceId) const;
    bool GetApplicationSyncType(int32_t& type);
    bool GetDataLength(int32_t& length);
    bool GetApplicationChangeList(std::vector<NotificationDistributedBundle>& applicationList);
};
}  // namespace Notification
}  // namespace OHOS
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_BUNDLE_ICON_BOX_H

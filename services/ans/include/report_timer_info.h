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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_REPORT_TIMER_INFO_H
#define BASE_NOTIFICATION_DISTRIBUTED_REPORT_TIMER_INFO_H

#include "notification_timer_info.h"
#include "in_process_call_wrapper.h"

namespace OHOS {
namespace Notification {
class ReportTimerInfo : public NotificationTimerInfo {
public:
    virtual ~ReportTimerInfo() {};
    ReportTimerInfo() {};
    /**
     * When timing is up, this function will execute as call back.
     */
    void OnTrigger() override;
};
} // namespace OHOS
} // namespace Notification
#endif  // BASE_NOTIFICATION_DISTRIBUTED_REPORT_TIMER_INFO_H

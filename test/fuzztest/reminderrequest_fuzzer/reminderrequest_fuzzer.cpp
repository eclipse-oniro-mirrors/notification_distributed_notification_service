/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#define private public
#define protected public
#include "reminder_request.h"
#undef private
#undef protected
#include "reminderrequest_fuzzer.h"

namespace OHOS {
    namespace {
        constexpr uint8_t ENABLE = 2;
        constexpr uint8_t ACTION_BUTTON_TYPE = 3;
        constexpr uint8_t COLUMN_TYPE = 2;
        constexpr uint8_t SLOT_TYPE_NUM = 5;
    }
    bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
    {
        std::string stringData(data);
        int32_t reminderId = static_cast<int32_t>(GetU32Data(data));
        Notification::ReminderRequest reminderRequest(reminderId);
        reminderRequest.CanRemove();
        reminderRequest.CanShow();
        reminderRequest.Dump();
        uint8_t types = *data % ACTION_BUTTON_TYPE;
        Notification::ReminderRequest::ActionButtonType type =
            Notification::ReminderRequest::ActionButtonType(types);
        reminderRequest.SetActionButton(stringData, type);
        reminderRequest.SetContent(stringData);
        reminderRequest.SetExpiredContent(stringData);
        bool enabled = *data % ENABLE;
        reminderRequest.SetExpired(enabled);
        reminderRequest.InitReminderId();
        reminderRequest.InitUserId(reminderId);
        reminderRequest.InitUid(reminderId);
        reminderRequest.IsExpired();
        reminderRequest.IsShowing();
        reminderRequest.OnClose(enabled);
        reminderRequest.OnDateTimeChange();
        uint64_t oriTriggerTime = 2;
        uint64_t optTriggerTimes = 2;
        reminderRequest.HandleSysTimeChange(oriTriggerTime, optTriggerTimes);
        uint64_t oldZoneTriggerTime = 1;
        uint64_t newZoneTriggerTime = 2;
        uint64_t optTriggerTime = 3;
        reminderRequest.HandleTimeZoneChange(oldZoneTriggerTime, newZoneTriggerTime, optTriggerTime);
        reminderRequest.OnSameNotificationIdCovered();
        reminderRequest.OnShow(enabled, enabled, enabled);
        reminderRequest.OnShowFail();
        reminderRequest.OnSnooze();
        reminderRequest.OnStart();
        reminderRequest.OnStop();
        reminderRequest.OnTerminate();
        reminderRequest.OnTimeZoneChange();
        std::shared_ptr<NativeRdb::AbsSharedResultSet> resultSet =
            std::make_shared<NativeRdb::AbsSharedResultSet>();
        uint8_t column = *data % COLUMN_TYPE;
        Notification::ReminderRequest::DbRecoveryType columnType =
            Notification::ReminderRequest::DbRecoveryType(column);
        reminderRequest.RecoverInt64FromDb(resultSet, stringData, columnType);
        reminderRequest.RecoverFromDb(resultSet);
        reminderRequest.RecoverActionButton(resultSet);
        reminderRequest.StringSplit(stringData, stringData);
        reminderRequest.RecoverWantAgent(stringData, *data);
        std::shared_ptr< Notification::ReminderRequest::MaxScreenAgentInfo> maxScreenWantAgentInfo =
            std::make_shared< Notification::ReminderRequest::MaxScreenAgentInfo>();
        reminderRequest.SetMaxScreenWantAgentInfo(maxScreenWantAgentInfo);
        reminderRequest.SetNotificationId(reminderId);
        uint8_t typed = *data % SLOT_TYPE_NUM;
        Notification::NotificationConstant::SlotType slotType =
            Notification::NotificationConstant::SlotType(typed);
        reminderRequest.SetSlotType(slotType);
        reminderRequest.SetSnoozeContent(stringData);
        return reminderRequest.ShouldShowImmediately();
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    char *ch = ParseData(data, size);
    if (ch != nullptr && size >= GetU32Size()) {
        OHOS::DoSomethingInterestingWithMyAPI(ch, size);
        free(ch);
        ch = nullptr;
    }
    return 0;
}

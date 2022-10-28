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
#include "ans_manager_stub.h"
#undef private
#undef protected
#include "ansmanagerstubannex_fuzzer.h"

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
    {
        Notification::AnsManagerStub ansManagerStub;
        MessageParcel datas;
        MessageParcel reply;
        ansManagerStub.HandleDelete(datas, reply);
        ansManagerStub.HandleDeleteByBundle(datas, reply);
        ansManagerStub.HandleDeleteAll(datas, reply);
        ansManagerStub.HandleGetSlotsByBundle(datas, reply);
        ansManagerStub.HandleUpdateSlots(datas, reply);
        ansManagerStub.HandleRequestEnableNotification(datas, reply);
        ansManagerStub.HandleSetNotificationsEnabledForBundle(datas, reply);
        ansManagerStub.HandleSetNotificationsEnabledForAllBundles(datas, reply);
        ansManagerStub.HandleSetNotificationsEnabledForSpecialBundle(datas, reply);
        ansManagerStub.HandleSetShowBadgeEnabledForBundle(datas, reply);
        ansManagerStub.HandleGetShowBadgeEnabledForBundle(datas, reply);
        ansManagerStub.HandleGetShowBadgeEnabled(datas, reply);
        ansManagerStub.HandleSubscribe(datas, reply);
        ansManagerStub.HandleUnsubscribe(datas, reply);
        ansManagerStub.HandleAreNotificationsSuspended(datas, reply);
        ansManagerStub.HandleGetCurrentAppSorting(datas, reply);
        ansManagerStub.HandleIsAllowedNotify(datas, reply);
        ansManagerStub.HandleIsAllowedNotifySelf(datas, reply);
        ansManagerStub.HandleIsSpecialBundleAllowedNotify(datas, reply);
        ansManagerStub.HandleCancelGroup(datas, reply);
        ansManagerStub.HandleRemoveGroupByBundle(datas, reply);
        ansManagerStub.HandleIsDistributedEnabled(datas, reply);
        ansManagerStub.HandleEnableDistributed(datas, reply);
        ansManagerStub.HandleEnableDistributedByBundle(datas, reply);
        ansManagerStub.HandleEnableDistributedSelf(datas, reply);
        ansManagerStub.HandleIsDistributedEnableByBundle(datas, reply);
        ansManagerStub.HandleGetDeviceRemindType(datas, reply);
        ansManagerStub.HandleShellDump(datas, reply);
        ansManagerStub.HandlePublishReminder(datas, reply);
        ansManagerStub.HandleCancelReminder(datas, reply);
        ansManagerStub.HandleCancelAllReminders(datas, reply);
        ansManagerStub.HandleGetValidReminders(datas, reply);
        ansManagerStub.HandleIsSupportTemplate(datas, reply);
        ansManagerStub.HandleIsSpecialUserAllowedNotifyByUser(datas, reply);
        ansManagerStub.HandleSetNotificationsEnabledByUser(datas, reply);
        ansManagerStub.HandleDeleteAllByUser(datas, reply);
        ansManagerStub.HandleSetDoNotDisturbDateByUser(datas, reply);
        ansManagerStub.HandleGetDoNotDisturbDateByUser(datas, reply);
        return ansManagerStub.HandleSetEnabledForBundleSlot(datas, reply);
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

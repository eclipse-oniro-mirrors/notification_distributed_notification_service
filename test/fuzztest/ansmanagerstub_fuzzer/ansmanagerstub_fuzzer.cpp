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
#include "ansmanagerstub_fuzzer.h"

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
    {
        std::string stringData(data);
        Notification::AnsManagerStub ansManagerStub;
        uint32_t code = GetU32Data(data);
        MessageParcel datas;
        MessageParcel reply;
        MessageOption flags;
        ansManagerStub.OnRemoteRequest(code, datas, reply, flags);
        ansManagerStub.HandlePublish(datas, reply);
        ansManagerStub.HandlePublishToDevice(datas, reply);
        ansManagerStub.HandleCancel(datas, reply);
        ansManagerStub.HandleCancelAll(datas, reply);
        ansManagerStub.HandleCancelAsBundle(datas, reply);
        ansManagerStub.HandleAddSlotByType(datas, reply);
        ansManagerStub.HandleAddSlots(datas, reply);
        ansManagerStub.HandleRemoveSlotByType(datas, reply);
        ansManagerStub.HandleRemoveAllSlots(datas, reply);
        ansManagerStub.HandleGetSlots(datas, reply);
        ansManagerStub.HandleGetSlotByType(datas, reply);
        ansManagerStub.HandleGetSlotNumAsBundle(datas, reply);
        ansManagerStub.HandleGetActiveNotifications(datas, reply);
        ansManagerStub.HandleGetActiveNotificationNums(datas, reply);
        ansManagerStub.HandleGetAllActiveNotifications(datas, reply);
        ansManagerStub.HandleGetSpecialActiveNotifications(datas, reply);
        ansManagerStub.HandleSetNotificationAgent(datas, reply);
        ansManagerStub.HandleGetNotificationAgent(datas, reply);
        ansManagerStub.HandleCanPublishAsBundle(datas, reply);
        ansManagerStub.HandlePublishAsBundle(datas, reply);
        ansManagerStub.HandleSetNotificationBadgeNum(datas, reply);
        ansManagerStub.HandleGetBundleImportance(datas, reply);
        ansManagerStub.HandleSetDoNotDisturbDate(datas, reply);
        ansManagerStub.HandleGetDoNotDisturbDate(datas, reply);
        ansManagerStub.HandleDoesSupportDoNotDisturbMode(datas, reply);
        ansManagerStub.HandlePublishContinuousTaskNotification(datas, reply);
        ansManagerStub.HandleCancelContinuousTaskNotification(datas, reply);
        ansManagerStub.HandleIsNotificationPolicyAccessGranted(datas, reply);
        ansManagerStub.HandleSetPrivateNotificationsAllowed(datas, reply);
        ansManagerStub.HandleGetPrivateNotificationsAllowed(datas, reply);
        ansManagerStub.HandleRemoveNotification(datas, reply);
        return ansManagerStub.HandleRemoveAllNotifications(datas, reply);
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

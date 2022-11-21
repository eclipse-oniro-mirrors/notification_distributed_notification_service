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
#include "notification_request.h"
#undef private
#undef protected
#include "notificationrequestannex_fuzzer.h"

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
    {
        int32_t notificationId = static_cast<int32_t>(GetU32Data(data));
        Notification::NotificationRequest request(notificationId);
        pid_t pid = *data;
        request.SetCreatorPid(pid);
        request.Dump();
        nlohmann::json jsonObject;
        request.ToJson(jsonObject);
        request.FromJson(jsonObject);
        request.ConvertObjectsToJson(jsonObject);
        request.ConvertObjectsToJson(jsonObject);
        Notification::NotificationRequest* target = new Notification::NotificationRequest(notificationId);
        request.ConvertJsonToNum(target, jsonObject);
        request.ConvertJsonToString(target, jsonObject);
        request.ConvertJsonToEnum(target, jsonObject);
        request.ConvertJsonToBool(target, jsonObject);
        request.ConvertJsonToPixelMap(target, jsonObject);
        request.ConvertJsonToNotificationContent(target, jsonObject);
        request.ConvertJsonToNotificationActionButton(target, jsonObject);
        request.ConvertJsonToNotificationDistributedOptions(target, jsonObject);
        request.ConvertJsonToNotificationFlags(target, jsonObject);
        return request.IsAgentNotification();
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

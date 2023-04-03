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
#include "ans_subscriber_proxy.h"
#undef private
#undef protected
#include "anssubscriberproxy_fuzzer.h"
#include "notification_request.h"
#include "notification_subscriber.h"

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
    {
        sptr<IRemoteObject> impl;
        Notification::AnsSubscriberProxy ansSubscriberProxy(impl);
        uint32_t code = GetU32Data(data);
        MessageParcel datas;
        MessageParcel reply;
        MessageOption flags;
        // test InnerTransact function
        ansSubscriberProxy.InnerTransact(code, flags, datas, reply);
        // test InnerTransact function
        ansSubscriberProxy.OnConnected();
        // test InnerTransact function
        ansSubscriberProxy.OnDisconnected();
        // test InnerTransact function
        sptr<Notification::Notification> notification = new Notification::Notification();
        ansSubscriberProxy.OnConsumed(notification);
        // test InnerTransact function
        sptr<Notification::NotificationSortingMap> notificationMap = new Notification::NotificationSortingMap();
        ansSubscriberProxy.OnConsumed(notification, notificationMap);
        // test OnCanceled function
        int32_t deleteReason = 1;
        ansSubscriberProxy.OnCanceled(notification, notificationMap, deleteReason);
        // test OnCanceled function
        ansSubscriberProxy.OnUpdated(notificationMap);
        // test OnCanceled function
        sptr<Notification::NotificationDoNotDisturbDate> date = new Notification::NotificationDoNotDisturbDate();
        ansSubscriberProxy.OnDoNotDisturbDateChange(date);
        // test OnEnabledNotificationChanged function
        sptr<Notification::EnabledNotificationCallbackData> callbackData = new Notification::EnabledNotificationCallbackData();
        ansSubscriberProxy.OnEnabledNotificationChanged(callbackData);
        return true;
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

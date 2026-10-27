/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "notification_classification.h"
#undef private
#undef protected

#include "notificationclassification_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace Notification {
    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
    {
        std::string classification = fdp->ConsumeRandomLengthString();
        std::string subClassification = fdp->ConsumeRandomLengthString();

        // Test constructor with parameters
        NotificationClassification notificationClassification(classification, subClassification);

        // Test SetClassification/GetClassification
        std::string newClassification = fdp->ConsumeRandomLengthString();
        notificationClassification.SetClassification(newClassification);
        notificationClassification.GetClassification();

        // Test SetSubClassification/GetSubClassification
        std::string newSubClassification = fdp->ConsumeRandomLengthString();
        notificationClassification.SetSubClassification(newSubClassification);
        notificationClassification.GetSubClassification();

        // Test Dump
        notificationClassification.Dump();

        // Test Marshalling/Unmarshalling
        Parcel parcel;
        notificationClassification.Marshalling(parcel);
        NotificationClassification::Unmarshalling(parcel);

        // Test default constructor
        NotificationClassification defaultClassification;
        defaultClassification.SetClassification(fdp->ConsumeRandomLengthString());
        defaultClassification.SetSubClassification(fdp->ConsumeRandomLengthString());
        defaultClassification.GetClassification();
        defaultClassification.GetSubClassification();
        defaultClassification.Dump();

        Parcel parcel2;
        defaultClassification.Marshalling(parcel2);
        NotificationClassification::Unmarshalling(parcel2);

        // Hostile parcel level injection (TEST-03 / SEC-01): the round trips above only
        // ever feed Unmarshalling its own legal output, while the real attack surface is
        // a crafted or corrupted parcel reaching Unmarshalling directly (a compromised
        // client can forge the string length prefix or truncate the payload, bypassing
        // the setter validation entirely, which is exactly how a malicious priority
        // triple would try to sneak in). Feed the remaining raw fuzz bytes as the parcel
        // buffer: Unmarshalling must tolerate arbitrary bytes (forged lengths, truncated
        // payloads, extreme int64/int32 values) without crashing, hanging or escaping
        // the value range handling. The write and read cursors of a parcel are
        // independent (the round trips above rely on the same behavior), so the bytes
        // written here are read back by Unmarshalling from the start.
        Parcel hostileParcel;
        std::string hostileBytes = fdp->ConsumeRemainingBytesAsString();
        if (!hostileBytes.empty()) {
            hostileParcel.WriteBuffer(hostileBytes.c_str(), hostileBytes.size());
            NotificationClassification::Unmarshalling(hostileParcel);
        }

        return true;
    }
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::Notification::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}

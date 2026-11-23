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

#define private public    // NOLINT
#define protected public  // NOLINT
#include "notification_check_info.h"
#include "notification_check_request.h"
#undef private
#undef protected
#include <memory>
#include <fuzzer/FuzzedDataProvider.h>
#include "notificationcheckrequest_fuzzer.h"

namespace OHOS {
namespace Notification {

constexpr uint8_t CONTENT_TYPE_MAX = 10;
constexpr uint8_t SLOT_TYPE_MAX = 9;

static void TestNotificationCheckRequest(FuzzedDataProvider* fuzzData)
{
    uint8_t contentTypeValue = fuzzData->ConsumeIntegral<uint8_t>() % CONTENT_TYPE_MAX;
    uint8_t slotTypeValue = fuzzData->ConsumeIntegral<uint8_t>() % SLOT_TYPE_MAX;
    NotificationContent::Type contentType = static_cast<NotificationContent::Type>(contentTypeValue);
    NotificationConstant::SlotType slotType = static_cast<NotificationConstant::SlotType>(slotTypeValue);

    std::vector<std::string> extraKeys;
    extraKeys.emplace_back(fuzzData->ConsumeRandomLengthString());
    extraKeys.emplace_back(fuzzData->ConsumeRandomLengthString());

    NotificationCheckRequest request(contentType, slotType, extraKeys);
    request.GetContentType();
    request.GetSlotType();
    request.GetExtraKeys();

    NotificationCheckRequest request2;
    request2.SetContentType(contentType);
    request2.SetSlotType(slotType);
    request2.SetExtraKeys(extraKeys);
    request2.SetUid(fuzzData->ConsumeIntegral<int32_t>());
    request2.GetUid();

    Parcel parcel;
    if (!request2.Marshalling(parcel)) {
        return;
    }
    auto unmarshalledRequest = std::unique_ptr<NotificationCheckRequest>(
        NotificationCheckRequest::Unmarshalling(parcel));
    if (unmarshalledRequest != nullptr) {
        // NotificationCheckRequest::Dump() is declared in the header but never defined, calling it fails to link.
        unmarshalledRequest->GetContentType();
        unmarshalledRequest->GetSlotType();
        unmarshalledRequest->GetExtraKeys();
        unmarshalledRequest->GetUid();
    }
}

static void TestNotificationCheckInfo(FuzzedDataProvider* fuzzData)
{
    std::string pkgName = fuzzData->ConsumeRandomLengthString();
    int32_t notifyId = fuzzData->ConsumeIntegral<int32_t>();
    int32_t contentType = fuzzData->ConsumeIntegral<int32_t>();
    int32_t creatorUserId = fuzzData->ConsumeIntegral<int32_t>();
    int32_t slotType = fuzzData->ConsumeIntegral<int32_t>();

    NotificationCheckInfo info;
    info.SetPkgName(pkgName);
    info.GetPkgName();
    info.SetNotifyId(notifyId);
    info.GetNotifyId();
    info.SetContentType(contentType);
    info.GetContentType();
    info.SetCreatorUserId(creatorUserId);
    info.GetCreatorUserId();
    info.SetSlotType(slotType);
    info.GetSlotType();
    info.SetLabel(fuzzData->ConsumeRandomLengthString());
    info.GetLabel();
    info.GetExtraInfo();

    std::string jsonData = fuzzData->ConsumeRandomLengthString();
    // ConvertJsonStringToValue() calls nlohmann::json::parse() without guarding parse errors, so a
    // malformed input would abort the fuzzer instead of being reported as a test case. accept()
    // reports a parse failure as a return value instead of throwing, so it works with any exception
    // configuration of the build.
    if (nlohmann::json::accept(jsonData)) {
        info.ConvertJsonStringToValue(jsonData);
        info.GetPkgName();
        info.GetNotifyId();
        info.GetLabel();
    }

    // A well-formed object built from fuzz data is needed as well, otherwise the body of
    // ConvertJsonStringToValue() is never reached and the field branches below stay uncovered.
    nlohmann::json jsonObject;
    jsonObject["pkgName"] = fuzzData->ConsumeRandomLengthString();
    jsonObject["notifyId"] = fuzzData->ConsumeIntegral<int32_t>();
    jsonObject["contentType"] = fuzzData->ConsumeIntegral<int32_t>();
    jsonObject["creatorUserId"] = fuzzData->ConsumeIntegral<int32_t>();
    jsonObject["slotType"] = fuzzData->ConsumeIntegral<int32_t>();
    jsonObject["label"] = fuzzData->ConsumeRandomLengthString();
    info.ConvertJsonStringToValue(jsonObject.dump());
    info.GetPkgName();
    info.GetNotifyId();
    info.GetCreatorUserId();
    info.GetSlotType();
    info.GetLabel();
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider* fuzzData)
{
    TestNotificationCheckRequest(fuzzData);
    TestNotificationCheckInfo(fuzzData);
    return true;
}
}  // namespace Notification
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fuzzData(data, size);
    OHOS::Notification::DoSomethingInterestingWithMyAPI(&fuzzData);
    return 0;
}

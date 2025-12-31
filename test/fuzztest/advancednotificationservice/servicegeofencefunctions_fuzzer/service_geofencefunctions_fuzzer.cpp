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
#include "service_geofencefunctions_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#define private public
#define protected public
#include "advanced_notification_service.h"
#undef private
#undef protected
#include "ans_permission_def.h"
#include "mock_notification_request.h"
#include "notification_request.h"

namespace OHOS {
namespace Notification {
namespace {
    constexpr uint8_t TRIGGER_TYPE_SIZE = 1;
    constexpr uint8_t COORDINATE_SYSTEM_TYPE_SIZE = 2;
    constexpr uint8_t MONITOR_EVENT_SIZE = 2;
    constexpr uint8_t CONFIG_PATH_SIZE = 2;
    constexpr uint32_t INTEGRAL_RANGE_SIZE = 100;
}

    std::shared_ptr<NotificationGeofence> GenerateGeofenceCondition(FuzzedDataProvider *fuzzData)
    {
        std::shared_ptr<NotificationGeofence> condition =
            std::make_shared<NotificationGeofence>();
        condition->SetLatitude(fuzzData->ConsumeFloatingPoint<double>());
        condition->SetLongitude(fuzzData->ConsumeFloatingPoint<double>());
        condition->SetRadius(fuzzData->ConsumeFloatingPoint<double>());
        condition->SetDelayTime(fuzzData->ConsumeIntegral<int32_t>());
        condition->SetCoordinateSystemType(static_cast<NotificationConstant::CoordinateSystemType>(
            fuzzData->ConsumeIntegralInRange<int32_t>(1, COORDINATE_SYSTEM_TYPE_SIZE)));
        condition->SetMonitorEvent(static_cast<NotificationConstant::MonitorEvent>(
            fuzzData->ConsumeIntegralInRange<int32_t>(1, MONITOR_EVENT_SIZE)));
        return condition;
    }

    std::shared_ptr<NotificationTrigger> GenerateNotificationTrigger(FuzzedDataProvider *fuzzData,
        const std::shared_ptr<NotificationGeofence> &condition)
    {
        std::shared_ptr<NotificationTrigger> trigger =
            std::make_shared<NotificationTrigger>();
        trigger->SetConfigPath(static_cast<NotificationConstant::ConfigPath>(
            fuzzData->ConsumeIntegralInRange<int32_t>(1, CONFIG_PATH_SIZE)));
        trigger->SetTriggerType(static_cast<NotificationConstant::TriggerType>(
            fuzzData->ConsumeIntegralInRange<int32_t>(1, TRIGGER_TYPE_SIZE)));
        trigger->SetGeofence(condition);
        trigger->SetDisplayTime(fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE));
        return trigger;
    }

    sptr<NotificationRequest> GenerateNotificationRequest(FuzzedDataProvider *fuzzData,
        const std::shared_ptr<NotificationTrigger> &trigger)
    {
        int32_t nid = fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE);
        sptr<NotificationRequest> request = new NotificationRequest(nid);
        std::string bundleName = fuzzData->ConsumeRandomLengthString();
        int32_t creatorUserId = fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE);
        int32_t recvUserId = fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE);
        int32_t uid = fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE);
        int32_t ownerId = fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE);
        auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
        request->SetOwnerBundleName(bundleName);
        request->SetCreatorUserId(creatorUserId);
        request->SetReceiverUserId(recvUserId);
        request->SetSlotType(slotType);
        request->SetOwnerUid(uid);
        request->SetOwnerUserId(ownerId);
        request->SetNotificationTrigger(trigger);
        return request;
    }

    void CallParameterRelatedFunctions(FuzzedDataProvider *fuzzData,
        const std::shared_ptr<NotificationRecord> &record,
        const sptr<AdvancedNotificationService> &service)
    {
        AdvancedNotificationService::PublishNotificationParameter parameter;
        parameter.request = record->request;
        parameter.bundleOption = record->bundleOption;
        parameter.isUpdateByOwner = fuzzData->ConsumeBool();
        parameter.tokenCaller = fuzzData->ConsumeIntegral<uint32_t>();
        parameter.uid = fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE);

        service->OnNotifyDelayedNotification(parameter);
        service->UpdateTriggerNotification(parameter);
        auto value = fuzzData->ConsumeRandomLengthString();
        service->ParseGeofenceNotificationFromDb(value, parameter);
        service->SetTriggerNotificationRequestToDb(parameter);
        service->PublishPreparedNotificationInner(parameter);
        auto key = fuzzData->ConsumeRandomLengthString();
        std::shared_ptr<NotificationRecord> outRecord;
        service->GetDelayedNotificationParameterByTriggerKey(key, parameter, outRecord);
        service->OnNotifyDelayedNotificationInner(parameter, record);
    }

    void CallRecordRelatedFunctions(FuzzedDataProvider *fuzzData,
        const std::shared_ptr<NotificationRecord> &record,
        const sptr<AdvancedNotificationService> &service)
    {
        service->AddToTriggerNotificationList(record);
        service->ProcForDeleteGeofenceLiveView(record);
        service->UpdateTriggerRecord(record, record);
        service->TriggerNotificationRecordFilter(record);
    }

    void CallRequestRelatedFunctions(FuzzedDataProvider *fuzzData,
        const sptr<NotificationRequest> &request,
        const sptr<NotificationBundleOption> bundleOption,
        const sptr<AdvancedNotificationService> &service)
    {
        service->CheckGeofenceNotificationRequest(request, bundleOption);
        auto requestParam = request;
        service->UpdateTriggerRequest(requestParam);
        service->CheckTriggerNotificationRequest(request);
        service->CheckSwitchStatus(request, bundleOption);
        service->CheckGeofenceNotificationRequestLiveViewStatus(request);
        service->CheckLiveViewPendingCreateLiveViewStatus(request);
        service->CheckLiveViewPendingEndLiveViewStatus(request);
        service->IsGeofenceNotificationRequest(request);
        service->IsExistsGeofence(request);
    }

    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
    {
        auto service = AdvancedNotificationService::GetInstance();
        service->InitPublishProcess();
        service->CreateDialogManager();
        auto condition = GenerateGeofenceCondition(fuzzData);
        auto trigger = GenerateNotificationTrigger(fuzzData, condition);
        auto request = GenerateNotificationRequest(fuzzData, trigger);
        std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
        record->request = request;
        record->notification = new Notification(request);
        sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
        bundleOption->SetBundleName(fuzzData->ConsumeRandomLengthString());
        bundleOption->SetUid(fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE));
        record->bundleOption = bundleOption;

        auto userId = fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE);
        service->ClearAllGeofenceNotificationRequests(userId);
        auto key = fuzzData->ConsumeRandomLengthString();
        std::vector<std::shared_ptr<NotificationRecord>> outRecords;
        service->FindGeofenceNotificationRecordByKey(key, outRecords);
        std::shared_ptr<NotificationRecord> outRecord;
        service->FindGeofenceNotificationRecordByTriggerKey(key, outRecord);
        service->FindNotificationRecordByKey(key, outRecord);
        service->RecoverGeofenceLiveViewFromDb(userId);
        service->RemoveTriggerNotificationListByTriggerKey(key);
        std::vector<AdvancedNotificationService::PublishNotificationParameter> parameters;
        service->GetBatchNotificationRequestsFromDb(parameters, userId);
        auto groupName = fuzzData->ConsumeRandomLengthString();
        service->ExecuteCancelGroupCancelFromTriggerNotificationList(bundleOption, groupName);
        NotificationKey notificationKey;
        auto nid = fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE);
        notificationKey.id = nid;
        auto label = fuzzData->ConsumeRandomLengthString();
        notificationKey.label = label;
        service->RemoveFromTriggerNotificationList(bundleOption, notificationKey);
        service->DeleteAllByUserStoppedFromTriggerNotificationList(key, userId);
        service->ExecuteRemoveNotificationFromTriggerNotificationList(bundleOption, nid, label);
        service->RemoveGroupByBundleFromTriggerNotificationList(bundleOption, groupName);
        AdvancedNotificationService::PublishNotificationParameter outParameter;
        auto isUpdateByOwner = fuzzData->ConsumeBool();
        service->GeneratePublishNotificationParameter(request, bundleOption, isUpdateByOwner, outParameter);
        CallParameterRelatedFunctions(fuzzData, record, service);
        CallRecordRelatedFunctions(fuzzData, record, service);
        CallRequestRelatedFunctions(fuzzData, request, bundleOption, service);
        service->SelfClean();
        return true;
    }
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    std::vector<std::string> requestPermission = {
        OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_CONTROLLER,
        OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER,
        OHOS::Notification::OHOS_PERMISSION_SET_UNREMOVABLE_NOTIFICATION
    };
    MockRandomToken(&fdp, requestPermission);
    OHOS::Notification::DoSomethingInterestingWithMyAPI(&fdp);
    constexpr int sleepMs = 1000;
    std::this_thread::sleep_for(std::chrono::milliseconds(sleepMs));
    return 0;
}
